use super::traits::{Tool, ToolResult};
use crate::config::schema::RebelOpsConfig;
use crate::security::policy::ToolOperation;
use crate::security::SecurityPolicy;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use reqwest::Method;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct RebelOpsAiConversationTool {
    security: Arc<SecurityPolicy>,
    client: RebelOpsAiConversationClient,
}

#[derive(Clone)]
struct RebelOpsAiConversationClient {
    config: RebelOpsConfig,
    client: reqwest::Client,
}

#[derive(Debug, Clone)]
struct AuthSession {
    access_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinkedOrganization {
    slug: String,
    organization_url: String,
}

#[derive(Debug, Deserialize)]
struct SupabasePasswordGrantResponse {
    access_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AccountLinkedOrganizationRow {
    organizations: Option<AccountLinkedOrganization>,
}

#[derive(Debug, Deserialize)]
struct AccountLinkedOrganization {
    slug: Option<String>,
    deleted_at: Option<String>,
    platform_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AiConversationResponse {
    #[serde(default)]
    messages: Vec<AiConversationMessage>,
    total: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct AiConversationMessage {
    id: Option<i64>,
    project_id: Option<i64>,
    supabase_user_id: Option<String>,
    role: Option<String>,
    content: Option<String>,
    content_encrypted: Option<String>,
    tool_name: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

impl RebelOpsAiConversationTool {
    pub fn new(security: Arc<SecurityPolicy>, config: RebelOpsConfig) -> Self {
        Self {
            security,
            client: RebelOpsAiConversationClient::new(config),
        }
    }

    async fn run(&self, args: Value) -> Result<ToolResult> {
        if let Err(error) = self
            .security
            .enforce_tool_operation(ToolOperation::Read, self.name())
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(error),
            });
        }

        let organization_slug =
            optional_string_arg(&args, &["organizationSlug", "organization_slug"])?;
        let project_id = required_i64_arg(&args, &["projectId", "project_id"])?;
        let limit = optional_usize_arg(&args, &["limit"])?
            .unwrap_or(20)
            .clamp(1, 100);

        let payload = self
            .client
            .list_project_conversation(organization_slug.as_deref(), project_id, limit)
            .await?;

        Ok(json_tool_result(payload))
    }
}

#[async_trait]
impl Tool for RebelOpsAiConversationTool {
    fn name(&self) -> &str {
        "rebelops_get_project_chat_history"
    }

    fn description(&self) -> &str {
        "Read the AI chat history for a specific RebelOps project for the current bot-linked member. Returns the most recent project conversation messages, including encrypted-message markers when plain text is unavailable."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "organizationSlug": {
                    "type": "string",
                    "description": "Organization slug. Optional when the bot account is linked to exactly one RebelOps organization."
                },
                "projectId": {
                    "type": "integer",
                    "description": "Project ID whose AI chat history should be read."
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of most recent messages to return (default: 20, max: 100)."
                }
            },
            "required": ["projectId"]
        })
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        self.run(args).await
    }
}

impl RebelOpsAiConversationClient {
    fn new(config: RebelOpsConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.config.timeout_ms.max(1_000))
    }

    fn build_supabase_token_url(&self) -> Result<reqwest::Url> {
        let mut url = reqwest::Url::parse(&self.config.supabase_url).with_context(|| {
            format!(
                "Invalid RebelOps supabase_url: {}",
                self.config.supabase_url
            )
        })?;
        url.set_path("/auth/v1/token");
        url.set_query(Some("grant_type=password"));
        Ok(url)
    }

    fn build_linked_organizations_url(&self) -> Result<reqwest::Url> {
        let mut url = reqwest::Url::parse(&self.config.supabase_url).with_context(|| {
            format!(
                "Invalid RebelOps supabase_url: {}",
                self.config.supabase_url
            )
        })?;
        url.set_path("/rest/v1/account_linked_organizations");
        url.query_pairs_mut()
            .append_pair(
                "select",
                "id,created_at,organization_id,organizations(id,slug,deleted_at,platform_url)",
            )
            .append_pair("order", "created_at.asc");
        Ok(url)
    }

    fn build_organization_api_url(
        &self,
        organization_url: &str,
        path_suffix: &str,
    ) -> Result<reqwest::Url> {
        let mut url = reqwest::Url::parse(organization_url)
            .with_context(|| format!("Invalid RebelOps organization URL: {organization_url}"))?;
        let base_path = if self.config.api_base_path.starts_with('/') {
            self.config.api_base_path.trim_end_matches('/').to_string()
        } else {
            format!("/{}", self.config.api_base_path.trim_matches('/'))
        };
        let suffix = path_suffix.trim_start_matches('/');
        if suffix.is_empty() {
            url.set_path(&base_path);
        } else {
            url.set_path(&format!("{base_path}/{suffix}"));
        }
        url.set_query(None);
        Ok(url)
    }

    async fn get_auth_session(&self) -> Result<AuthSession> {
        let username = self
            .config
            .username
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .context("RebelOps chat history tools require channels.rebelops.username")?;
        let password = self
            .config
            .password
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .context("RebelOps chat history tools require channels.rebelops.password")?;

        let response = self
            .client
            .post(self.build_supabase_token_url()?)
            .header("content-type", "application/json")
            .header("apikey", self.config.supabase_anon_key.clone())
            .header(
                "authorization",
                format!("Bearer {}", self.config.supabase_anon_key),
            )
            .timeout(self.timeout())
            .json(&json!({
                "email": username,
                "password": password,
            }))
            .send()
            .await
            .context("Failed to sign in to RebelOps via Supabase")?;

        if !response.status().is_success() {
            bail!(
                "RebelOps sign-in failed: {}",
                read_json_error_body(response).await
            );
        }

        let payload: SupabasePasswordGrantResponse = response
            .json()
            .await
            .context("Failed to parse RebelOps Supabase auth response")?;

        let access_token = payload
            .access_token
            .filter(|value| !value.trim().is_empty())
            .context("RebelOps sign-in succeeded but access_token was missing")?;

        Ok(AuthSession { access_token })
    }

    async fn list_linked_organizations(
        &self,
        session: &AuthSession,
    ) -> Result<Vec<LinkedOrganization>> {
        let response = self
            .client
            .get(self.build_linked_organizations_url()?)
            .header("apikey", self.config.supabase_anon_key.clone())
            .header("authorization", format!("Bearer {}", session.access_token))
            .header("content-type", "application/json")
            .timeout(self.timeout())
            .send()
            .await
            .context("Failed to list linked RebelOps organizations")?;

        if !response.status().is_success() {
            bail!(
                "Failed to list linked RebelOps organizations: {}",
                read_json_error_body(response).await
            );
        }

        let rows: Vec<AccountLinkedOrganizationRow> = response
            .json()
            .await
            .context("Failed to parse linked RebelOps organizations response")?;

        let organizations = rows
            .into_iter()
            .filter_map(|row| row.organizations)
            .filter(|details| details.deleted_at.is_none())
            .filter_map(|details| {
                let slug = details.slug?.trim().to_ascii_lowercase();
                let organization_url = details.platform_url?.trim().to_string();
                if slug.is_empty() || organization_url.is_empty() {
                    return None;
                }
                Some(LinkedOrganization {
                    slug,
                    organization_url,
                })
            })
            .collect::<Vec<_>>();

        if organizations.is_empty() {
            bail!("This RebelOps bot account is not linked to any active organizations");
        }

        Ok(organizations)
    }

    async fn resolve_organization(
        &self,
        requested_slug: Option<&str>,
    ) -> Result<(AuthSession, LinkedOrganization)> {
        let session = self.get_auth_session().await?;
        let organizations = self.list_linked_organizations(&session).await?;

        let organization = if let Some(slug) = requested_slug
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            organizations
                .into_iter()
                .find(|organization| organization.slug.eq_ignore_ascii_case(slug))
                .with_context(|| {
                    format!("RebelOps organization '{slug}' is not linked to this bot account")
                })?
        } else if organizations.len() == 1 {
            organizations
                .into_iter()
                .next()
                .expect("single organization")
        } else {
            let available = organizations
                .iter()
                .map(|organization| organization.slug.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "organizationSlug is required because this RebelOps bot account is linked to multiple organizations: {available}"
            );
        };

        Ok((session, organization))
    }

    async fn list_project_conversation(
        &self,
        requested_slug: Option<&str>,
        project_id: i64,
        limit: usize,
    ) -> Result<Value> {
        let (session, organization) = self.resolve_organization(requested_slug).await?;
        let response: AiConversationResponse = self
            .request_json(
                Method::GET,
                &session.access_token,
                &organization,
                &format!("projects/{project_id}/ai-conversation"),
            )
            .await?;

        let total = response.total.unwrap_or(response.messages.len());
        let start = response.messages.len().saturating_sub(limit);
        let recent = response
            .messages
            .into_iter()
            .skip(start)
            .collect::<Vec<_>>();

        Ok(json!({
            "organizationSlug": organization.slug,
            "projectId": project_id,
            "total": total,
            "returned": recent.len(),
            "messages": recent.into_iter().map(|message| {
                json!({
                    "id": message.id,
                    "projectId": message.project_id,
                    "supabaseUserId": message.supabase_user_id,
                    "role": message.role,
                    "content": message.content,
                    "contentEncrypted": message.content_encrypted,
                    "toolName": message.tool_name,
                    "createdAt": message.created_at,
                    "updatedAt": message.updated_at,
                })
            }).collect::<Vec<_>>()
        }))
    }

    async fn request_json<T: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        access_token: &str,
        organization: &LinkedOrganization,
        path_suffix: &str,
    ) -> Result<T> {
        let url = self.build_organization_api_url(&organization.organization_url, path_suffix)?;
        let response = self
            .client
            .request(method.clone(), url)
            .header("authorization", format!("Bearer {access_token}"))
            .header("content-type", "application/json")
            .timeout(self.timeout())
            .send()
            .await
            .with_context(|| {
                format!(
                    "Failed to call RebelOps endpoint '{}': {path_suffix}",
                    method
                )
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let message = read_json_error_body(response).await;
            bail!("RebelOps chat history request failed ({status}): {message}");
        }

        response
            .json::<T>()
            .await
            .context("Failed to parse RebelOps chat history response as JSON")
    }
}

fn json_tool_result(payload: Value) -> ToolResult {
    ToolResult {
        success: true,
        output: serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string()),
        error: None,
    }
}

async fn read_json_error_body(response: reqwest::Response) -> String {
    let status = response.status();
    match response.json::<Value>().await {
        Ok(value) => {
            for key in ["msg", "message", "error_description", "error"] {
                if let Some(text) = value.get(key).and_then(Value::as_str) {
                    return text.to_string();
                }
            }
            format!("HTTP {status}")
        }
        Err(_) => format!("HTTP {status}"),
    }
}

fn optional_string_arg(args: &Value, names: &[&str]) -> Result<Option<String>> {
    for name in names {
        if let Some(value) = args.get(*name) {
            if value.is_null() {
                return Ok(None);
            }
            let text = value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| anyhow!("'{name}' must be a non-empty string when provided"))?;
            return Ok(Some(text));
        }
    }
    Ok(None)
}

fn optional_usize_arg(args: &Value, names: &[&str]) -> Result<Option<usize>> {
    for name in names {
        if let Some(value) = args.get(*name) {
            let number = value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .or_else(|| {
                    value.as_i64().and_then(|value| {
                        if value > 0 {
                            usize::try_from(value).ok()
                        } else {
                            None
                        }
                    })
                })
                .or_else(|| {
                    value
                        .as_str()
                        .and_then(|text| text.trim().parse::<usize>().ok())
                })
                .ok_or_else(|| anyhow!("'{name}' must be a positive integer"))?;
            return Ok(Some(number));
        }
    }
    Ok(None)
}

fn optional_i64_arg(args: &Value, names: &[&str]) -> Result<Option<i64>> {
    for name in names {
        if let Some(value) = args.get(*name) {
            if let Some(number) = value_as_i64(value) {
                return Ok(Some(number));
            }
            bail!("'{name}' must be an integer");
        }
    }
    Ok(None)
}

fn required_i64_arg(args: &Value, names: &[&str]) -> Result<i64> {
    optional_i64_arg(args, names)?
        .ok_or_else(|| anyhow!("Missing required parameter '{}'", names[0]))
}

fn value_as_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|number| i64::try_from(number).ok()))
        .or_else(|| {
            value
                .as_str()
                .and_then(|text| text.trim().parse::<i64>().ok())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityPolicy;
    use reqwest::StatusCode;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_security() -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy::default())
    }

    fn rebelops_config(base_url: &str) -> RebelOpsConfig {
        RebelOpsConfig {
            username: Some("bot@example.com".to_string()),
            password: Some("Password123!".to_string()),
            supabase_url: base_url.to_string(),
            supabase_anon_key: "anon-key".to_string(),
            timeout_ms: 5_000,
            ..RebelOpsConfig::default()
        }
    }

    async fn mount_auth(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/auth/v1/token"))
            .respond_with(ResponseTemplate::new(StatusCode::OK).set_body_json(json!({
                "access_token": "token-123"
            })))
            .mount(server)
            .await;
    }

    async fn mount_linked_organizations(server: &MockServer, organizations: &[(&str, &str)]) {
        let payload = organizations
            .iter()
            .map(|(slug, url)| {
                json!({
                    "organizations": {
                        "slug": slug,
                        "deleted_at": null,
                        "platform_url": url,
                    }
                })
            })
            .collect::<Vec<_>>();

        Mock::given(method("GET"))
            .and(path("/rest/v1/account_linked_organizations"))
            .respond_with(ResponseTemplate::new(StatusCode::OK).set_body_json(payload))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn list_project_chat_history_returns_recent_messages() {
        let server = MockServer::start().await;
        mount_auth(&server).await;
        mount_linked_organizations(&server, &[("alpha", &server.uri())]).await;

        Mock::given(method("GET"))
            .and(path("/api/projects/77/ai-conversation"))
            .respond_with(ResponseTemplate::new(StatusCode::OK).set_body_json(json!({
                "messages": [
                    {"id": 1, "project_id": 77, "role": "user", "content": "First", "content_encrypted": null, "tool_name": null, "created_at": "2026-03-31T10:00:00Z", "updated_at": "2026-03-31T10:00:00Z"},
                    {"id": 2, "project_id": 77, "role": "assistant", "content": "Second", "content_encrypted": null, "tool_name": null, "created_at": "2026-03-31T10:01:00Z", "updated_at": "2026-03-31T10:01:00Z"},
                    {"id": 3, "project_id": 77, "role": "user", "content": null, "content_encrypted": "ciphertext", "tool_name": null, "created_at": "2026-03-31T10:02:00Z", "updated_at": "2026-03-31T10:02:00Z"}
                ],
                "total": 3
            })))
            .mount(&server)
            .await;

        let tool = RebelOpsAiConversationTool::new(test_security(), rebelops_config(&server.uri()));
        let result = tool
            .execute(json!({ "projectId": 77, "limit": 2 }))
            .await
            .unwrap();

        assert!(result.success);
        let payload: Value = serde_json::from_str(&result.output).unwrap();
        assert_eq!(payload["total"], json!(3));
        assert_eq!(payload["returned"], json!(2));
        assert_eq!(payload["messages"][0]["id"], json!(2));
        assert_eq!(
            payload["messages"][1]["contentEncrypted"],
            json!("ciphertext")
        );
    }
}
