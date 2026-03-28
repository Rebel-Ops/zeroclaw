use super::traits::{Tool, ToolResult};
use crate::config::schema::RebelOpsConfig;
use crate::security::policy::ToolOperation;
use crate::security::SecurityPolicy;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_NOTES_EXTENSION_ID: i64 = 5;
const NOTES_SOURCE_IDENTIFIER: &str = "rebelops/notes";

#[derive(Clone)]
pub struct RebelOpsNotesTool {
    operation: RebelOpsNotesOperation,
    security: Arc<SecurityPolicy>,
    client: RebelOpsNotesClient,
}

#[derive(Clone, Copy)]
enum RebelOpsNotesOperation {
    List,
    Get,
    ListProject,
    Create,
    Update,
    Delete,
}

#[derive(Clone)]
struct RebelOpsNotesClient {
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

impl RebelOpsNotesTool {
    pub fn list(security: Arc<SecurityPolicy>, config: RebelOpsConfig) -> Self {
        Self::new(RebelOpsNotesOperation::List, security, config)
    }

    pub fn get(security: Arc<SecurityPolicy>, config: RebelOpsConfig) -> Self {
        Self::new(RebelOpsNotesOperation::Get, security, config)
    }

    pub fn list_project(security: Arc<SecurityPolicy>, config: RebelOpsConfig) -> Self {
        Self::new(RebelOpsNotesOperation::ListProject, security, config)
    }

    pub fn create(security: Arc<SecurityPolicy>, config: RebelOpsConfig) -> Self {
        Self::new(RebelOpsNotesOperation::Create, security, config)
    }

    pub fn update(security: Arc<SecurityPolicy>, config: RebelOpsConfig) -> Self {
        Self::new(RebelOpsNotesOperation::Update, security, config)
    }

    pub fn delete(security: Arc<SecurityPolicy>, config: RebelOpsConfig) -> Self {
        Self::new(RebelOpsNotesOperation::Delete, security, config)
    }

    fn new(
        operation: RebelOpsNotesOperation,
        security: Arc<SecurityPolicy>,
        config: RebelOpsConfig,
    ) -> Self {
        Self {
            operation,
            security,
            client: RebelOpsNotesClient::new(config),
        }
    }

    fn operation_name(&self) -> &'static str {
        match self.operation {
            RebelOpsNotesOperation::List => "rebelops_list_notes",
            RebelOpsNotesOperation::Get => "rebelops_get_note",
            RebelOpsNotesOperation::ListProject => "rebelops_list_project_notes",
            RebelOpsNotesOperation::Create => "rebelops_create_note",
            RebelOpsNotesOperation::Update => "rebelops_update_note",
            RebelOpsNotesOperation::Delete => "rebelops_delete_note",
        }
    }

    fn operation_description(&self) -> &'static str {
        match self.operation {
            RebelOpsNotesOperation::List => {
                "List RebelOps notes for an organization, optionally filtered by extension or project."
            }
            RebelOpsNotesOperation::Get => "Fetch a single RebelOps note by ID.",
            RebelOpsNotesOperation::ListProject => {
                "List RebelOps notes for a project and its sub-projects."
            }
            RebelOpsNotesOperation::Create => {
                "Create a RebelOps note. Supports plain and encrypted fields."
            }
            RebelOpsNotesOperation::Update => {
                "Update an existing RebelOps note. Supports plain and encrypted fields."
            }
            RebelOpsNotesOperation::Delete => "Delete a RebelOps note by ID.",
        }
    }

    fn operation_type(&self) -> ToolOperation {
        match self.operation {
            RebelOpsNotesOperation::List
            | RebelOpsNotesOperation::Get
            | RebelOpsNotesOperation::ListProject => ToolOperation::Read,
            RebelOpsNotesOperation::Create
            | RebelOpsNotesOperation::Update
            | RebelOpsNotesOperation::Delete => ToolOperation::Act,
        }
    }

    fn base_properties() -> Map<String, Value> {
        let mut properties = Map::new();
        properties.insert(
            "organizationSlug".to_string(),
            json!({
                "type": "string",
                "description": "Organization slug. Optional when the bot account is linked to exactly one RebelOps organization."
            }),
        );
        properties
    }

    fn schema(&self) -> Value {
        let mut properties = Self::base_properties();
        let required = match self.operation {
            RebelOpsNotesOperation::List => {
                properties.insert(
                    "extensionId".to_string(),
                    json!({
                        "type": "integer",
                        "description": "Optional notes extension ID filter."
                    }),
                );
                properties.insert(
                    "projectId".to_string(),
                    json!({
                        "type": "integer",
                        "description": "Optional project ID filter."
                    }),
                );
                Vec::<&str>::new()
            }
            RebelOpsNotesOperation::Get => {
                properties.insert(
                    "noteId".to_string(),
                    json!({
                        "type": "integer",
                        "description": "Note ID to fetch."
                    }),
                );
                vec!["noteId"]
            }
            RebelOpsNotesOperation::ListProject => {
                properties.insert(
                    "projectId".to_string(),
                    json!({
                        "type": "integer",
                        "description": "Project ID whose hierarchy should be searched."
                    }),
                );
                properties.insert(
                    "extensionId".to_string(),
                    json!({
                        "type": "integer",
                        "description": "Optional notes extension ID filter."
                    }),
                );
                vec!["projectId"]
            }
            RebelOpsNotesOperation::Create => {
                properties.insert(
                    "extensionId".to_string(),
                    json!({
                        "type": "integer",
                        "description": "Optional notes extension ID. Defaults to the built-in RebelOps Notes extension when omitted."
                    }),
                );
                properties.insert(
                    "projectId".to_string(),
                    json!({
                        "type": "integer",
                        "description": "Optional project ID for the note."
                    }),
                );
                properties.insert(
                    "title".to_string(),
                    json!({
                        "type": "string",
                        "description": "Plain-text note title."
                    }),
                );
                properties.insert(
                    "titleEncrypted".to_string(),
                    json!({
                        "type": "string",
                        "description": "Encrypted note title."
                    }),
                );
                properties.insert(
                    "description".to_string(),
                    json!({
                        "type": "string",
                        "description": "Plain-text note description."
                    }),
                );
                properties.insert(
                    "descriptionEncrypted".to_string(),
                    json!({
                        "type": "string",
                        "description": "Encrypted note description."
                    }),
                );
                properties.insert(
                    "sortOrder".to_string(),
                    json!({
                        "type": "integer",
                        "description": "Optional sort order."
                    }),
                );
                properties.insert(
                    "onboarding".to_string(),
                    json!({
                        "type": "boolean",
                        "description": "Whether this note is onboarding content."
                    }),
                );
                Vec::<&str>::new()
            }
            RebelOpsNotesOperation::Update => {
                properties.insert(
                    "noteId".to_string(),
                    json!({
                        "type": "integer",
                        "description": "Note ID to update."
                    }),
                );
                properties.insert(
                    "title".to_string(),
                    json!({"type": "string", "description": "Updated plain-text title."}),
                );
                properties.insert(
                    "titleEncrypted".to_string(),
                    json!({"type": "string", "description": "Updated encrypted title."}),
                );
                properties.insert(
                    "description".to_string(),
                    json!({
                        "type": "string",
                        "description": "Updated plain-text description."
                    }),
                );
                properties.insert(
                    "descriptionEncrypted".to_string(),
                    json!({
                        "type": "string",
                        "description": "Updated encrypted description."
                    }),
                );
                properties.insert(
                    "sortOrder".to_string(),
                    json!({"type": "integer", "description": "Updated sort order."}),
                );
                properties.insert(
                    "onboarding".to_string(),
                    json!({
                        "type": "boolean",
                        "description": "Updated onboarding flag."
                    }),
                );
                vec!["noteId"]
            }
            RebelOpsNotesOperation::Delete => {
                properties.insert(
                    "noteId".to_string(),
                    json!({
                        "type": "integer",
                        "description": "Note ID to delete."
                    }),
                );
                vec!["noteId"]
            }
        };

        json!({
            "type": "object",
            "properties": properties,
            "required": required,
        })
    }

    async fn run(&self, args: Value) -> Result<ToolResult> {
        if let Err(error) = self
            .security
            .enforce_tool_operation(self.operation_type(), self.operation_name())
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(error),
            });
        }

        match self.operation {
            RebelOpsNotesOperation::List => self.list_notes(args).await,
            RebelOpsNotesOperation::Get => self.get_note(args).await,
            RebelOpsNotesOperation::ListProject => self.list_project_notes(args).await,
            RebelOpsNotesOperation::Create => self.create_note(args).await,
            RebelOpsNotesOperation::Update => self.update_note(args).await,
            RebelOpsNotesOperation::Delete => self.delete_note(args).await,
        }
    }

    async fn list_notes(&self, args: Value) -> Result<ToolResult> {
        let organization_slug =
            optional_string_arg(&args, &["organizationSlug", "organization_slug"])?;
        let project_id = optional_i64_arg(&args, &["projectId", "project_id"])?;
        let extension_id = optional_i64_arg(&args, &["extensionId", "extension_id"])?;

        let response = self
            .client
            .notes_get(
                organization_slug.as_deref(),
                "notes",
                extension_id,
                project_id,
                None,
            )
            .await?;

        Ok(json_tool_result(response))
    }

    async fn get_note(&self, args: Value) -> Result<ToolResult> {
        let organization_slug =
            optional_string_arg(&args, &["organizationSlug", "organization_slug"])?;
        let note_id = required_i64_arg(&args, &["noteId", "note_id"])?;

        let response = self
            .client
            .notes_get(
                organization_slug.as_deref(),
                &format!("notes/{note_id}"),
                None,
                None,
                None,
            )
            .await?;

        Ok(json_tool_result(response))
    }

    async fn list_project_notes(&self, args: Value) -> Result<ToolResult> {
        let organization_slug =
            optional_string_arg(&args, &["organizationSlug", "organization_slug"])?;
        let project_id = required_i64_arg(&args, &["projectId", "project_id"])?;
        let extension_id = optional_i64_arg(&args, &["extensionId", "extension_id"])?;

        let response = self
            .client
            .notes_get(
                organization_slug.as_deref(),
                &format!("notes/project/{project_id}"),
                extension_id,
                None,
                None,
            )
            .await?;

        Ok(json_tool_result(response))
    }

    async fn create_note(&self, args: Value) -> Result<ToolResult> {
        let organization_slug =
            optional_string_arg(&args, &["organizationSlug", "organization_slug"])?;
        let project_id = optional_i64_arg(&args, &["projectId", "project_id"])?;
        let title = optional_string_arg(&args, &["title"])?;
        let title_encrypted = optional_string_arg(&args, &["titleEncrypted", "title_encrypted"])?;
        let description = optional_string_arg(&args, &["description"])?;
        let description_encrypted =
            optional_string_arg(&args, &["descriptionEncrypted", "description_encrypted"])?;
        let sort_order = optional_i64_arg(&args, &["sortOrder", "sort_order"])?;
        let onboarding = optional_bool_arg(&args, &["onboarding"])?;

        if description.is_none() && description_encrypted.is_none() {
            bail!("rebelops_create_note requires either 'description' or 'descriptionEncrypted'");
        }

        let extension_id = self
            .client
            .resolve_notes_extension_id(
                organization_slug.as_deref(),
                optional_i64_arg(&args, &["extensionId", "extension_id"])?,
            )
            .await?;

        let mut body = Map::new();
        body.insert("extension_id".to_string(), json!(extension_id));
        insert_optional_i64(&mut body, "project_id", project_id);
        insert_optional_string(&mut body, "title", title);
        insert_optional_string(&mut body, "title_encrypted", title_encrypted);
        insert_optional_string(&mut body, "description", description);
        insert_optional_string(&mut body, "description_encrypted", description_encrypted);
        insert_optional_i64(&mut body, "sort_order", sort_order);
        insert_optional_bool(&mut body, "onboarding", onboarding);

        let response = self
            .client
            .notes_write(
                organization_slug.as_deref(),
                Method::POST,
                "notes",
                Value::Object(body),
            )
            .await?;

        Ok(json_tool_result(response))
    }

    async fn update_note(&self, args: Value) -> Result<ToolResult> {
        let organization_slug =
            optional_string_arg(&args, &["organizationSlug", "organization_slug"])?;
        let note_id = required_i64_arg(&args, &["noteId", "note_id"])?;

        let title = optional_string_arg(&args, &["title"])?;
        let title_encrypted = optional_string_arg(&args, &["titleEncrypted", "title_encrypted"])?;
        let description = optional_string_arg(&args, &["description"])?;
        let description_encrypted =
            optional_string_arg(&args, &["descriptionEncrypted", "description_encrypted"])?;
        let sort_order = optional_i64_arg(&args, &["sortOrder", "sort_order"])?;
        let onboarding = optional_bool_arg(&args, &["onboarding"])?;

        let mut body = Map::new();
        insert_optional_string(&mut body, "title", title);
        insert_optional_string(&mut body, "title_encrypted", title_encrypted);
        insert_optional_string(&mut body, "description", description);
        insert_optional_string(&mut body, "description_encrypted", description_encrypted);
        insert_optional_i64(&mut body, "sort_order", sort_order);
        insert_optional_bool(&mut body, "onboarding", onboarding);

        if body.is_empty() {
            bail!("rebelops_update_note requires at least one field to update");
        }

        let response = self
            .client
            .notes_write(
                organization_slug.as_deref(),
                Method::PUT,
                &format!("notes/{note_id}"),
                Value::Object(body),
            )
            .await?;

        Ok(json_tool_result(response))
    }

    async fn delete_note(&self, args: Value) -> Result<ToolResult> {
        let organization_slug =
            optional_string_arg(&args, &["organizationSlug", "organization_slug"])?;
        let note_id = required_i64_arg(&args, &["noteId", "note_id"])?;

        let response = self
            .client
            .notes_delete(organization_slug.as_deref(), &format!("notes/{note_id}"))
            .await?;

        Ok(json_tool_result(response))
    }
}

#[async_trait]
impl Tool for RebelOpsNotesTool {
    fn name(&self) -> &str {
        self.operation_name()
    }

    fn description(&self) -> &str {
        self.operation_description()
    }

    fn parameters_schema(&self) -> Value {
        self.schema()
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        self.run(args).await
    }
}

impl RebelOpsNotesClient {
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
            .context("RebelOps notes tools require channels.rebelops.username")?;
        let password = self
            .config
            .password
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .context("RebelOps notes tools require channels.rebelops.password")?;

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

    async fn resolve_notes_extension_id(
        &self,
        requested_slug: Option<&str>,
        explicit_extension_id: Option<i64>,
    ) -> Result<i64> {
        if let Some(extension_id) = explicit_extension_id {
            return Ok(extension_id);
        }

        let (session, organization) = self.resolve_organization(requested_slug).await?;
        match self
            .request_json(
                Method::GET,
                &session.access_token,
                &organization,
                "extensions",
                None,
                None,
            )
            .await
        {
            Ok(payload) => {
                let resolved = payload
                    .get("extensions")
                    .and_then(Value::as_array)
                    .and_then(|extensions| {
                        extensions.iter().find_map(|entry| {
                            let manifest = entry.get("manifest")?.as_object()?;
                            let source = manifest
                                .get("source")
                                .and_then(Value::as_str)
                                .unwrap_or_default();
                            let kind = manifest
                                .get("type")
                                .and_then(Value::as_str)
                                .unwrap_or_default();
                            if source.contains(NOTES_SOURCE_IDENTIFIER)
                                || kind.contains(NOTES_SOURCE_IDENTIFIER)
                            {
                                entry.get("id").and_then(value_as_i64)
                            } else {
                                None
                            }
                        })
                    });
                Ok(resolved.unwrap_or(DEFAULT_NOTES_EXTENSION_ID))
            }
            Err(_) => Ok(DEFAULT_NOTES_EXTENSION_ID),
        }
    }

    async fn notes_get(
        &self,
        requested_slug: Option<&str>,
        path_suffix: &str,
        extension_id: Option<i64>,
        project_id: Option<i64>,
        extra_query: Option<Map<String, Value>>,
    ) -> Result<Value> {
        let (session, organization) = self.resolve_organization(requested_slug).await?;
        let mut query = Map::new();
        insert_optional_i64(&mut query, "extension_id", extension_id);
        insert_optional_i64(&mut query, "project_id", project_id);
        if let Some(extra_query) = extra_query {
            query.extend(extra_query);
        }

        self.request_json(
            Method::GET,
            &session.access_token,
            &organization,
            path_suffix,
            if query.is_empty() { None } else { Some(query) },
            None,
        )
        .await
    }

    async fn notes_write(
        &self,
        requested_slug: Option<&str>,
        method: Method,
        path_suffix: &str,
        body: Value,
    ) -> Result<Value> {
        let (session, organization) = self.resolve_organization(requested_slug).await?;
        self.request_json(
            method,
            &session.access_token,
            &organization,
            path_suffix,
            None,
            Some(body),
        )
        .await
    }

    async fn notes_delete(&self, requested_slug: Option<&str>, path_suffix: &str) -> Result<Value> {
        let (session, organization) = self.resolve_organization(requested_slug).await?;
        self.request_json(
            Method::DELETE,
            &session.access_token,
            &organization,
            path_suffix,
            None,
            None,
        )
        .await
    }

    async fn request_json(
        &self,
        method: Method,
        access_token: &str,
        organization: &LinkedOrganization,
        path_suffix: &str,
        query: Option<Map<String, Value>>,
        body: Option<Value>,
    ) -> Result<Value> {
        let mut url =
            self.build_organization_api_url(&organization.organization_url, path_suffix)?;
        if let Some(query) = query.as_ref() {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                if let Some(value) = query_value_to_string(value) {
                    pairs.append_pair(key, &value);
                }
            }
            drop(pairs);
        }

        let mut request = self
            .client
            .request(method.clone(), url)
            .header("authorization", format!("Bearer {access_token}"))
            .header("content-type", "application/json")
            .timeout(self.timeout());

        if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
            request = request.json(&body.unwrap_or_else(|| json!({})));
        }

        let response = request.send().await.with_context(|| {
            format!(
                "Failed to call RebelOps endpoint '{}': {path_suffix}",
                method
            )
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let message = read_json_error_body(response).await;
            bail!("RebelOps notes request failed ({status}): {message}");
        }

        response
            .json::<Value>()
            .await
            .context("Failed to parse RebelOps notes response as JSON")
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
            if let Some(note) = value
                .get("message")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
            {
                return note.to_string();
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
        .ok_or_else(|| anyhow!("Missing required parameter '{}", names[0]))
}

fn optional_bool_arg(args: &Value, names: &[&str]) -> Result<Option<bool>> {
    for name in names {
        if let Some(value) = args.get(*name) {
            if let Some(boolean) = value.as_bool() {
                return Ok(Some(boolean));
            }
            if let Some(text) = value.as_str() {
                match text.trim().to_ascii_lowercase().as_str() {
                    "true" => return Ok(Some(true)),
                    "false" => return Ok(Some(false)),
                    _ => bail!("'{name}' must be a boolean"),
                }
            }
            bail!("'{name}' must be a boolean");
        }
    }
    Ok(None)
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

fn insert_optional_string(target: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(value) = value {
        target.insert(key.to_string(), Value::String(value));
    }
}

fn insert_optional_i64(target: &mut Map<String, Value>, key: &str, value: Option<i64>) {
    if let Some(value) = value {
        target.insert(key.to_string(), json!(value));
    }
}

fn insert_optional_bool(target: &mut Map<String, Value>, key: &str, value: Option<bool>) {
    if let Some(value) = value {
        target.insert(key.to_string(), json!(value));
    }
}

fn query_value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(text) => Some(text.clone()),
        Value::Bool(boolean) => Some(boolean.to_string()),
        Value::Number(number) => Some(number.to_string()),
        _ => Some(value.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{AutonomyLevel, SecurityPolicy};
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_security() -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy::default())
    }

    fn readonly_security() -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            ..SecurityPolicy::default()
        })
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
    async fn list_notes_defaults_to_single_linked_organization() {
        let server = MockServer::start().await;
        mount_auth(&server).await;
        mount_linked_organizations(&server, &[("alpha", &server.uri())]).await;

        Mock::given(method("GET"))
            .and(path("/api/notes"))
            .respond_with(ResponseTemplate::new(StatusCode::OK).set_body_json(json!({
                "notes": [{"id": 42, "title": "Ops note"}],
                "total": 1
            })))
            .mount(&server)
            .await;

        let tool = RebelOpsNotesTool::list(test_security(), rebelops_config(&server.uri()));
        let result = tool.execute(json!({ "projectId": 77 })).await.unwrap();

        assert!(result.success);
        let payload: Value = serde_json::from_str(&result.output).unwrap();
        assert_eq!(payload["total"], json!(1));
        assert_eq!(payload["notes"][0]["id"], json!(42));
    }

    #[tokio::test]
    async fn create_note_resolves_extension_id_and_posts_body() {
        let server = MockServer::start().await;
        mount_auth(&server).await;
        mount_linked_organizations(&server, &[("alpha", &server.uri())]).await;

        Mock::given(method("GET"))
            .and(path("/api/extensions"))
            .respond_with(ResponseTemplate::new(StatusCode::OK).set_body_json(json!({
                "extensions": [{
                    "id": 12,
                    "manifest": {
                        "source": "rebelops/notes",
                        "type": "rebelops/notes"
                    }
                }]
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/notes"))
            .and(body_partial_json(json!({
                "extension_id": 12,
                "project_id": 99,
                "description": "Build runbook",
                "onboarding": true
            })))
            .respond_with(
                ResponseTemplate::new(StatusCode::CREATED).set_body_json(json!({
                    "note": {"id": 7, "extension_id": 12, "project_id": 99}
                })),
            )
            .mount(&server)
            .await;

        let tool = RebelOpsNotesTool::create(test_security(), rebelops_config(&server.uri()));
        let result = tool
            .execute(json!({
                "projectId": 99,
                "description": "Build runbook",
                "onboarding": true
            }))
            .await
            .unwrap();

        assert!(result.success);
        let payload: Value = serde_json::from_str(&result.output).unwrap();
        assert_eq!(payload["note"]["id"], json!(7));
        assert_eq!(payload["note"]["extension_id"], json!(12));
    }

    #[tokio::test]
    async fn list_notes_requires_organization_slug_when_multiple_orgs() {
        let server = MockServer::start().await;
        mount_auth(&server).await;
        mount_linked_organizations(
            &server,
            &[("alpha", &server.uri()), ("beta", &server.uri())],
        )
        .await;

        let tool = RebelOpsNotesTool::list(test_security(), rebelops_config(&server.uri()));
        let result = tool.execute(json!({})).await;

        let error = result.unwrap_err().to_string();
        assert!(error.contains("organizationSlug is required"));
        assert!(error.contains("alpha"));
        assert!(error.contains("beta"));
    }

    #[tokio::test]
    async fn delete_note_is_blocked_in_readonly_mode() {
        let tool =
            RebelOpsNotesTool::delete(readonly_security(), rebelops_config("https://example.com"));
        let result = tool
            .execute(json!({ "organizationSlug": "alpha", "noteId": 1 }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("read-only mode"));
    }
}
