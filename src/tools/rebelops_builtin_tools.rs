use super::traits::{Tool, ToolResult};
use crate::config::schema::RebelOpsConfig;
use crate::security::policy::ToolOperation;
use crate::security::SecurityPolicy;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use reqwest::Method;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct RebelOpsBuiltInTool {
    spec: RebelOpsToolSpec,
    security: Arc<SecurityPolicy>,
    client: RebelOpsBuiltInClient,
}

#[derive(Clone)]
struct RebelOpsToolSpec {
    name: &'static str,
    description: &'static str,
    operation: ToolOperation,
    parameters_schema: Value,
    method: Method,
    path_template: &'static str,
    source_identifier: Option<&'static str>,
    path_params: Vec<ParameterMapping>,
    query_params: Vec<ParameterMapping>,
    body_params: Vec<ParameterMapping>,
}

#[derive(Clone)]
struct RebelOpsBuiltInClient {
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

#[derive(Clone, Copy)]
enum ValueTransform {
    Direct,
    RequirementsArray,
    AssignmentsArray,
    CustomFieldsArray,
}

#[derive(Clone)]
struct ParameterMapping {
    arg_name: &'static str,
    target_key: &'static str,
    transform: ValueTransform,
    resolve_extension: bool,
}

impl ParameterMapping {
    fn direct(arg_name: &'static str, target_key: &'static str) -> Self {
        Self {
            arg_name,
            target_key,
            transform: ValueTransform::Direct,
            resolve_extension: false,
        }
    }

    fn extension(arg_name: &'static str, target_key: &'static str) -> Self {
        Self {
            arg_name,
            target_key,
            transform: ValueTransform::Direct,
            resolve_extension: true,
        }
    }

    fn requirements(arg_name: &'static str, target_key: &'static str) -> Self {
        Self {
            arg_name,
            target_key,
            transform: ValueTransform::RequirementsArray,
            resolve_extension: false,
        }
    }

    fn assignments(arg_name: &'static str, target_key: &'static str) -> Self {
        Self {
            arg_name,
            target_key,
            transform: ValueTransform::AssignmentsArray,
            resolve_extension: false,
        }
    }

    fn custom_fields(arg_name: &'static str, target_key: &'static str) -> Self {
        Self {
            arg_name,
            target_key,
            transform: ValueTransform::CustomFieldsArray,
            resolve_extension: false,
        }
    }
}

impl RebelOpsBuiltInTool {
    fn new(
        spec: RebelOpsToolSpec,
        security: Arc<SecurityPolicy>,
        config: RebelOpsConfig,
    ) -> Self {
        Self {
            spec,
            security,
            client: RebelOpsBuiltInClient::new(config),
        }
    }

    pub fn all(
        security: Arc<SecurityPolicy>,
        config: RebelOpsConfig,
    ) -> Vec<Arc<dyn Tool>> {
        all_specs()
            .into_iter()
            .map(|spec| Arc::new(Self::new(spec, security.clone(), config.clone())) as Arc<dyn Tool>)
            .collect()
    }

    async fn run(&self, args: Value) -> Result<ToolResult> {
        if let Err(error) = self
            .security
            .enforce_tool_operation(self.spec.operation, self.spec.name)
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(error),
            });
        }

        let organization_slug = optional_string_arg(&args, "organizationSlug")?;
        let resolved_extension_id = self
            .resolve_extension_id_if_needed(organization_slug.as_deref(), &args)
            .await?;

        let path_suffix = self.build_path_suffix(&args, resolved_extension_id)?;
        let query = self.build_map(&self.spec.query_params, &args, resolved_extension_id)?;
        let body = self.build_map(&self.spec.body_params, &args, resolved_extension_id)?;

        let payload = self
            .client
            .request_json_for_slug(
                self.spec.method.clone(),
                organization_slug.as_deref(),
                &path_suffix,
                if query.is_empty() { None } else { Some(query) },
                if matches!(self.spec.method, Method::POST | Method::PUT | Method::PATCH) {
                    Some(Value::Object(body))
                } else {
                    None
                },
            )
            .await?;

        Ok(json_tool_result(payload))
    }

    async fn resolve_extension_id_if_needed(
        &self,
        organization_slug: Option<&str>,
        args: &Value,
    ) -> Result<Option<i64>> {
        let needs_extension = self
            .spec
            .path_params
            .iter()
            .chain(self.spec.query_params.iter())
            .chain(self.spec.body_params.iter())
            .any(|mapping| mapping.resolve_extension);

        if !needs_extension {
            return Ok(None);
        }

        let explicit = optional_i64_arg(args, "extensionId")?;
        let resolved = self
            .client
            .resolve_builtin_extension_id(organization_slug, explicit, self.spec.source_identifier)
            .await?;

        if resolved.is_none() && self.spec.requires_parameter("extensionId") {
            bail!(
                "{} requires 'extensionId' and the built-in extension could not be resolved automatically",
                self.spec.name
            );
        }

        Ok(resolved)
    }

    fn build_path_suffix(&self, args: &Value, resolved_extension_id: Option<i64>) -> Result<String> {
        let mut path = self.spec.path_template.trim_start_matches('/').to_string();

        for mapping in &self.spec.path_params {
            let value = self.mapping_value(mapping, args, resolved_extension_id, true)?;
            let value = value.ok_or_else(|| anyhow!("Missing required parameter '{}'", mapping.arg_name))?;
            let replacement = path_segment_string(&value)
                .ok_or_else(|| anyhow!("'{}' must be a string or integer", mapping.arg_name))?;
            path = path.replace(&format!(":{}", mapping.target_key), &replacement);
        }

        Ok(path)
    }

    fn build_map(
        &self,
        mappings: &[ParameterMapping],
        args: &Value,
        resolved_extension_id: Option<i64>,
    ) -> Result<Map<String, Value>> {
        let mut map = Map::new();
        for mapping in mappings {
            if let Some(value) = self.mapping_value(mapping, args, resolved_extension_id, false)? {
                map.insert(mapping.target_key.to_string(), value);
            }
        }
        Ok(map)
    }

    fn mapping_value(
        &self,
        mapping: &ParameterMapping,
        args: &Value,
        resolved_extension_id: Option<i64>,
        required: bool,
    ) -> Result<Option<Value>> {
        if mapping.resolve_extension {
            if let Some(explicit) = find_arg(args, mapping.arg_name) {
                return Ok(Some(explicit.clone()));
            }
            if let Some(extension_id) = resolved_extension_id {
                return Ok(Some(json!(extension_id)));
            }
            if required {
                bail!("Missing required parameter '{}'", mapping.arg_name);
            }
            return Ok(None);
        }

        match mapping.transform {
            ValueTransform::Direct => Ok(find_arg(args, mapping.arg_name).cloned()),
            ValueTransform::RequirementsArray => transform_requirements(find_arg(args, mapping.arg_name)),
            ValueTransform::AssignmentsArray => transform_assignments(find_arg(args, mapping.arg_name)),
            ValueTransform::CustomFieldsArray => transform_custom_fields(find_arg(args, mapping.arg_name)),
        }
    }
}

#[async_trait]
impl Tool for RebelOpsBuiltInTool {
    fn name(&self) -> &str {
        self.spec.name
    }

    fn description(&self) -> &str {
        self.spec.description
    }

    fn parameters_schema(&self) -> Value {
        self.spec.parameters_schema.clone()
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        self.run(args).await
    }
}

impl RebelOpsToolSpec {
    fn requires_parameter(&self, name: &str) -> bool {
        self.parameters_schema
            .get("required")
            .and_then(Value::as_array)
            .map(|items| items.iter().any(|item| item.as_str() == Some(name)))
            .unwrap_or(false)
    }
}

impl RebelOpsBuiltInClient {
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
        let mut url = reqwest::Url::parse(&self.config.supabase_url)
            .with_context(|| format!("Invalid RebelOps supabase_url: {}", self.config.supabase_url))?;
        url.set_path("/auth/v1/token");
        url.set_query(Some("grant_type=password"));
        Ok(url)
    }

    fn build_linked_organizations_url(&self) -> Result<reqwest::Url> {
        let mut url = reqwest::Url::parse(&self.config.supabase_url)
            .with_context(|| format!("Invalid RebelOps supabase_url: {}", self.config.supabase_url))?;
        url.set_path("/rest/v1/account_linked_organizations");
        {
            let mut pairs = url.query_pairs_mut();
            pairs
                .append_pair("select", "id,created_at,organization_id,organizations(id,slug,deleted_at,platform_url)")
                .append_pair("order", "created_at.asc");
        }
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
            .context("RebelOps built-in tools require channels.rebelops.username")?;
        let password = self
            .config
            .password
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .context("RebelOps built-in tools require channels.rebelops.password")?;

        let response = self
            .client
            .post(self.build_supabase_token_url()?)
            .header("content-type", "application/json")
            .header("apikey", self.config.supabase_anon_key.clone())
            .header("authorization", format!("Bearer {}", self.config.supabase_anon_key))
            .timeout(self.timeout())
            .json(&json!({ "email": username, "password": password }))
            .send()
            .await
            .context("Failed to sign in to RebelOps via Supabase")?;

        if !response.status().is_success() {
            bail!("RebelOps sign-in failed: {}", read_json_error_body(response).await);
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
                Some(LinkedOrganization { slug, organization_url })
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
            organizations.into_iter().next().expect("single organization")
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

    async fn resolve_builtin_extension_id(
        &self,
        requested_slug: Option<&str>,
        explicit_extension_id: Option<i64>,
        source_identifier: Option<&str>,
    ) -> Result<Option<i64>> {
        if explicit_extension_id.is_some() || source_identifier.is_none() {
            return Ok(explicit_extension_id);
        }

        let (session, organization) = self.resolve_organization(requested_slug).await?;
        let payload = self
            .request_json(
                Method::GET,
                Some(session),
                Some(organization),
                "extensions",
                None,
                None,
            )
            .await?;

        let resolved = payload
            .get("extensions")
            .and_then(Value::as_array)
            .and_then(|extensions| {
                extensions.iter().find_map(|entry| {
                    let manifest = entry.get("manifest")?.as_object()?;
                    let source = manifest.get("source").and_then(Value::as_str).unwrap_or_default();
                    let kind = manifest.get("type").and_then(Value::as_str).unwrap_or_default();
                    if source_identifier
                        .is_some_and(|needle| source.contains(needle) || kind.contains(needle))
                    {
                        entry.get("id").and_then(value_as_i64)
                    } else {
                        None
                    }
                })
            });

        Ok(resolved)
    }

    async fn request_json_for_slug(
        &self,
        method: Method,
        requested_slug: Option<&str>,
        path_suffix: &str,
        query: Option<Map<String, Value>>,
        body: Option<Value>,
    ) -> Result<Value> {
        let (session, organization) = self.resolve_organization(requested_slug).await?;
        self.request_json(
            method,
            Some(session),
            Some(organization),
            path_suffix,
            query,
            body,
        )
        .await
    }

    async fn request_json(
        &self,
        method: Method,
        session: Option<AuthSession>,
        organization: Option<LinkedOrganization>,
        path_suffix: &str,
        query: Option<Map<String, Value>>,
        body: Option<Value>,
    ) -> Result<Value> {
        let (session, organization) = match (session, organization) {
            (Some(session), Some(organization)) => (session, organization),
            _ => self.resolve_organization(None).await?,
        };

        let mut url = self.build_organization_api_url(&organization.organization_url, path_suffix)?;
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
            .header("authorization", format!("Bearer {}", session.access_token))
            .header("content-type", "application/json")
            .timeout(self.timeout());

        if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
            request = request.json(&body.unwrap_or_else(|| json!({})));
        }

        let response = request.send().await.with_context(|| {
            format!("Failed to call RebelOps endpoint '{}': {}", method, path_suffix)
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let message = read_json_error_body(response).await;
            bail!("RebelOps request failed ({status}): {message}");
        }

        response
            .json::<Value>()
            .await
            .context("Failed to parse RebelOps response as JSON")
    }
}

fn find_arg<'a>(args: &'a Value, name: &str) -> Option<&'a Value> {
    if let Some(value) = args.get(name) {
        return Some(value);
    }
    let snake = camel_to_snake(name);
    args.get(&snake)
}

fn camel_to_snake(name: &str) -> String {
    let mut output = String::with_capacity(name.len() + 4);
    for (index, ch) in name.chars().enumerate() {
        if ch.is_uppercase() {
            if index > 0 {
                output.push('_');
            }
            output.extend(ch.to_lowercase());
        } else {
            output.push(ch);
        }
    }
    output
}

fn optional_string_arg(args: &Value, name: &str) -> Result<Option<String>> {
    let Some(value) = find_arg(args, name) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let text = value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("'{name}' must be a non-empty string when provided"))?;
    Ok(Some(text))
}

fn optional_i64_arg(args: &Value, name: &str) -> Result<Option<i64>> {
    let Some(value) = find_arg(args, name) else {
        return Ok(None);
    };
    value_as_i64(value).ok_or_else(|| anyhow!("'{name}' must be an integer")).map(Some)
}

fn value_as_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|number| i64::try_from(number).ok()))
        .or_else(|| value.as_str().and_then(|text| text.trim().parse::<i64>().ok()))
}

fn path_segment_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(boolean) => Some(boolean.to_string()),
        _ => None,
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

fn transform_requirements(value: Option<&Value>) -> Result<Option<Value>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let items = value
        .as_array()
        .ok_or_else(|| anyhow!("'requirements' must be an array"))?;
    let mut output = Vec::with_capacity(items.len());
    for item in items {
        let object = item
            .as_object()
            .ok_or_else(|| anyhow!("Each requirements entry must be an object"))?;
        let role_id = find_object_value(object, "roleId")
            .or_else(|| find_object_value(object, "role_id"))
            .and_then(value_as_i64)
            .ok_or_else(|| anyhow!("Each requirements entry must include an integer roleId"))?;
        let quantity = find_object_value(object, "quantity")
            .and_then(value_as_i64)
            .ok_or_else(|| anyhow!("Each requirements entry must include an integer quantity"))?;
        output.push(json!({
            "role_id": role_id,
            "quantity": quantity,
        }));
    }
    Ok(Some(Value::Array(output)))
}

fn transform_assignments(value: Option<&Value>) -> Result<Option<Value>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let items = value
        .as_array()
        .ok_or_else(|| anyhow!("'assignments' must be an array"))?;
    let mut output = Vec::with_capacity(items.len());
    for item in items {
        let object = item
            .as_object()
            .ok_or_else(|| anyhow!("Each assignments entry must be an object"))?;
        let staff_id = find_object_value(object, "staffId")
            .or_else(|| find_object_value(object, "staff_id"))
            .and_then(value_as_i64)
            .ok_or_else(|| anyhow!("Each assignments entry must include an integer staffId"))?;
        let shift_id = find_object_value(object, "shiftId")
            .or_else(|| find_object_value(object, "shift_id"))
            .and_then(value_as_i64)
            .ok_or_else(|| anyhow!("Each assignments entry must include an integer shiftId"))?;
        let mut payload = Map::new();
        payload.insert("staff_id".to_string(), json!(staff_id));
        payload.insert("shift_id".to_string(), json!(shift_id));
        if let Some(date) = find_object_value(object, "date").cloned() {
            payload.insert("date".to_string(), date);
        }
        output.push(Value::Object(payload));
    }
    Ok(Some(Value::Array(output)))
}

fn transform_custom_fields(value: Option<&Value>) -> Result<Option<Value>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let items = value
        .as_array()
        .ok_or_else(|| anyhow!("'customFields' must be an array"))?;
    let mut output = Vec::with_capacity(items.len());
    for item in items {
        let object = item
            .as_object()
            .ok_or_else(|| anyhow!("Each customFields entry must be an object"))?;
        let custom_field_id = find_object_value(object, "customFieldId")
            .or_else(|| find_object_value(object, "custom_field_id"))
            .and_then(value_as_i64)
            .ok_or_else(|| anyhow!("Each customFields entry must include an integer customFieldId"))?;
        let mut payload = Map::new();
        payload.insert("custom_field_id".to_string(), json!(custom_field_id));
        if let Some(value) = find_object_value(object, "value").cloned() {
            payload.insert("value".to_string(), value);
        }
        if let Some(value) = find_object_value(object, "valueEncrypted")
            .or_else(|| find_object_value(object, "value_encrypted"))
            .cloned()
        {
            payload.insert("value_encrypted".to_string(), value);
        }
        output.push(Value::Object(payload));
    }
    Ok(Some(Value::Array(output)))
}

fn find_object_value<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    if let Some(value) = object.get(key) {
        return Some(value);
    }
    let snake = camel_to_snake(key);
    object.get(&snake)
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

fn tool_spec(
    name: &'static str,
    description: &'static str,
    operation: ToolOperation,
    parameters_schema: Value,
    method: Method,
    path_template: &'static str,
    source_identifier: Option<&'static str>,
    path_params: Vec<ParameterMapping>,
    query_params: Vec<ParameterMapping>,
    body_params: Vec<ParameterMapping>,
) -> RebelOpsToolSpec {
    RebelOpsToolSpec {
        name,
        description,
        operation,
        parameters_schema: with_org_scope(parameters_schema),
        method,
        path_template,
        source_identifier,
        path_params,
        query_params,
        body_params,
    }
}

fn with_org_scope(mut schema: Value) -> Value {
    if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
        properties.insert(
            "organizationSlug".to_string(),
            json!({
                "type": "string",
                "description": "Organization slug. Optional when the bot account is linked to exactly one RebelOps organization."
            }),
        );
    }
    schema
}

fn string_prop(description: &str) -> Value {
    json!({ "type": "string", "description": description })
}

fn integer_prop(description: &str) -> Value {
    json!({ "type": "integer", "description": description })
}

fn boolean_prop(description: &str) -> Value {
    json!({ "type": "boolean", "description": description })
}

fn datetime_prop(description: &str) -> Value {
    json!({ "type": "string", "format": "date-time", "description": description })
}

fn string_array_prop(description: &str) -> Value {
    json!({ "type": "array", "items": { "type": "string" }, "description": description })
}

fn int_array_prop(description: &str) -> Value {
    json!({ "type": "array", "items": { "type": "integer" }, "description": description })
}

fn requirements_prop() -> Value {
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "roleId": { "type": "integer" },
                "quantity": { "type": "integer" }
            },
            "required": ["roleId"]
        },
        "description": "Shift staffing requirements"
    })
}

fn assignments_prop() -> Value {
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "staffId": { "type": "integer" },
                "shiftId": { "type": "integer" },
                "date": { "type": "string", "format": "date-time" }
            },
            "required": ["staffId", "shiftId"]
        },
        "description": "Shift assignments"
    })
}

fn custom_fields_prop() -> Value {
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "customFieldId": { "type": "integer" },
                "value": { "type": "string" },
                "valueEncrypted": { "type": "string" }
            },
            "required": ["customFieldId"]
        },
        "description": "CRM custom field payloads"
    })
}

fn object_prop(description: &str) -> Value {
    json!({ "type": "object", "description": description })
}

fn schema(properties: Vec<(&str, Value)>, required: &[&str], any_of: Option<Value>) -> Value {
    let mut map = Map::new();
    for (key, value) in properties {
        map.insert(key.to_string(), value);
    }
    let mut schema = json!({
        "type": "object",
        "properties": map,
        "required": required,
    });
    if let Some(any_of) = any_of {
        schema["anyOf"] = any_of;
    }
    schema
}

fn all_specs() -> Vec<RebelOpsToolSpec> {
    let mut specs = Vec::new();

    specs.extend(calendar_specs());
    specs.extend(tasks_specs());
    specs.extend(decisions_specs());
    specs.extend(news_specs());
    specs.extend(git_repository_specs());
    specs.extend(crm_specs());
    specs.extend(shifts_specs());
    specs.extend(time_tracking_specs());

    specs
}

fn calendar_specs() -> Vec<RebelOpsToolSpec> {
    vec![
        tool_spec(
            "rebelops_list_calendar_events",
            "List RebelOps calendar events with optional project and date filters.",
            ToolOperation::Read,
            schema(
                vec![
                    ("extensionId", integer_prop("Calendar extension ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("startDate", datetime_prop("Start date filter")),
                    ("endDate", datetime_prop("End date filter")),
                ],
                &[],
                None,
            ),
            Method::GET,
            "calendar/events",
            Some("rebelops/calendar"),
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("startDate", "start_date"),
                ParameterMapping::direct("endDate", "end_date"),
            ],
            vec![],
        ),
        tool_spec(
            "rebelops_list_project_calendar_events",
            "List RebelOps calendar events for a project hierarchy.",
            ToolOperation::Read,
            schema(
                vec![
                    ("projectId", integer_prop("Project ID")),
                    ("extensionId", integer_prop("Calendar extension ID")),
                    ("startDate", datetime_prop("Start date filter")),
                    ("endDate", datetime_prop("End date filter")),
                ],
                &["projectId"],
                None,
            ),
            Method::GET,
            "calendar/events/project/:projectId",
            Some("rebelops/calendar"),
            vec![ParameterMapping::direct("projectId", "projectId")],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("startDate", "start_date"),
                ParameterMapping::direct("endDate", "end_date"),
            ],
            vec![],
        ),
        tool_spec(
            "rebelops_create_calendar_event",
            "Create a RebelOps calendar event.",
            ToolOperation::Act,
            schema(
                vec![
                    ("extensionId", integer_prop("Calendar extension ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("title", string_prop("Event title")),
                    ("titleEncrypted", string_prop("Encrypted event title")),
                    ("description", string_prop("Event description")),
                    ("descriptionEncrypted", string_prop("Encrypted event description")),
                    ("startTime", datetime_prop("Event start time")),
                    ("endTime", datetime_prop("Event end time")),
                    ("assignees", string_array_prop("Supabase user IDs to assign")),
                ],
                &["projectId", "startTime", "endTime"],
                None,
            ),
            Method::POST,
            "calendar/events",
            Some("rebelops/calendar"),
            vec![],
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("title", "title"),
                ParameterMapping::direct("titleEncrypted", "title_encrypted"),
                ParameterMapping::direct("description", "description"),
                ParameterMapping::direct("descriptionEncrypted", "description_encrypted"),
                ParameterMapping::direct("startTime", "start_time"),
                ParameterMapping::direct("endTime", "end_time"),
                ParameterMapping::direct("assignees", "assignees"),
            ],
        ),
        tool_spec(
            "rebelops_update_calendar_event",
            "Update a RebelOps calendar event.",
            ToolOperation::Act,
            schema(
                vec![
                    ("eventId", integer_prop("Event ID")),
                    ("title", string_prop("Updated title")),
                    ("titleEncrypted", string_prop("Encrypted title")),
                    ("description", string_prop("Updated description")),
                    ("descriptionEncrypted", string_prop("Encrypted description")),
                    ("startTime", datetime_prop("Updated start time")),
                    ("endTime", datetime_prop("Updated end time")),
                    ("assignees", string_array_prop("Updated assignees")),
                ],
                &["eventId"],
                None,
            ),
            Method::PUT,
            "calendar/events/:eventId",
            Some("rebelops/calendar"),
            vec![ParameterMapping::direct("eventId", "eventId")],
            vec![],
            vec![
                ParameterMapping::direct("title", "title"),
                ParameterMapping::direct("titleEncrypted", "title_encrypted"),
                ParameterMapping::direct("description", "description"),
                ParameterMapping::direct("descriptionEncrypted", "description_encrypted"),
                ParameterMapping::direct("startTime", "start_time"),
                ParameterMapping::direct("endTime", "end_time"),
                ParameterMapping::direct("assignees", "assignees"),
            ],
        ),
        tool_spec(
            "rebelops_delete_calendar_event",
            "Delete a RebelOps calendar event.",
            ToolOperation::Act,
            schema(vec![("eventId", integer_prop("Event ID"))], &["eventId"], None),
            Method::DELETE,
            "calendar/events/:eventId",
            Some("rebelops/calendar"),
            vec![ParameterMapping::direct("eventId", "eventId")],
            vec![],
            vec![],
        ),
    ]
}

fn tasks_specs() -> Vec<RebelOpsToolSpec> {
    vec![
        tool_spec(
            "rebelops_list_project_tasks",
            "List RebelOps tasks for a project.",
            ToolOperation::Read,
            schema(
                vec![
                    ("projectId", integer_prop("Project ID")),
                    ("extensionId", integer_prop("Tasks extension ID")),
                    ("completed", boolean_prop("Completion filter")),
                    ("assignedTo", string_prop("Supabase assignee ID")),
                ],
                &["projectId", "extensionId"],
                None,
            ),
            Method::GET,
            "tasks",
            Some("rebelops/tasks"),
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("completed", "completed"),
                ParameterMapping::direct("assignedTo", "assigned_to"),
            ],
            vec![],
        ),
        tool_spec(
            "rebelops_list_tasks_by_assignee",
            "List RebelOps tasks assigned to a specific user.",
            ToolOperation::Read,
            schema(
                vec![
                    ("assignedTo", string_prop("Supabase assignee ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("extensionId", integer_prop("Tasks extension ID")),
                    ("completed", boolean_prop("Completion filter")),
                ],
                &["assignedTo"],
                None,
            ),
            Method::GET,
            "tasks",
            Some("rebelops/tasks"),
            vec![],
            vec![
                ParameterMapping::direct("assignedTo", "assigned_to"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("completed", "completed"),
            ],
            vec![],
        ),
        tool_spec(
            "rebelops_get_task",
            "Fetch a single RebelOps task.",
            ToolOperation::Read,
            schema(vec![("taskId", integer_prop("Task ID"))], &["taskId"], None),
            Method::GET,
            "tasks/:taskId",
            Some("rebelops/tasks"),
            vec![ParameterMapping::direct("taskId", "taskId")],
            vec![],
            vec![],
        ),
        tool_spec(
            "rebelops_list_task_assignees",
            "List assignees for a RebelOps task.",
            ToolOperation::Read,
            schema(vec![("taskId", integer_prop("Task ID"))], &["taskId"], None),
            Method::GET,
            "tasks/:taskId/assignees",
            Some("rebelops/tasks"),
            vec![ParameterMapping::direct("taskId", "taskId")],
            vec![],
            vec![],
        ),
        tool_spec(
            "rebelops_create_task",
            "Create a RebelOps task.",
            ToolOperation::Act,
            schema(
                vec![
                    ("extensionId", integer_prop("Tasks extension ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("title", string_prop("Task title")),
                    ("titleEncrypted", string_prop("Encrypted task title")),
                    ("description", string_prop("Task description")),
                    ("descriptionEncrypted", string_prop("Encrypted task description")),
                    ("priority", string_prop("Task priority")),
                    ("dueDate", datetime_prop("Due date")),
                    ("tags", string_array_prop("Tags")),
                    ("tagsEncrypted", string_prop("Encrypted tags payload")),
                    ("assignees", string_array_prop("Assignees")),
                ],
                &["extensionId", "projectId", "title"],
                None,
            ),
            Method::POST,
            "tasks",
            Some("rebelops/tasks"),
            vec![],
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("title", "title"),
                ParameterMapping::direct("titleEncrypted", "title_encrypted"),
                ParameterMapping::direct("description", "description"),
                ParameterMapping::direct("descriptionEncrypted", "description_encrypted"),
                ParameterMapping::direct("priority", "priority"),
                ParameterMapping::direct("dueDate", "due_date"),
                ParameterMapping::direct("tags", "tags"),
                ParameterMapping::direct("tagsEncrypted", "tags_encrypted"),
                ParameterMapping::direct("assignees", "assignees"),
            ],
        ),
        tool_spec(
            "rebelops_update_task",
            "Update a RebelOps task.",
            ToolOperation::Act,
            schema(
                vec![
                    ("taskId", integer_prop("Task ID")),
                    ("title", string_prop("Updated title")),
                    ("titleEncrypted", string_prop("Encrypted title")),
                    ("description", string_prop("Updated description")),
                    ("descriptionEncrypted", string_prop("Encrypted description")),
                    ("priority", string_prop("Updated priority")),
                    ("dueDate", datetime_prop("Updated due date")),
                    ("completed", boolean_prop("Completion state")),
                    ("tags", string_array_prop("Updated tags")),
                    ("tagsEncrypted", string_prop("Encrypted tags payload")),
                    ("assignees", string_array_prop("Updated assignees")),
                ],
                &["taskId"],
                None,
            ),
            Method::PUT,
            "tasks/:taskId",
            Some("rebelops/tasks"),
            vec![ParameterMapping::direct("taskId", "taskId")],
            vec![],
            vec![
                ParameterMapping::direct("title", "title"),
                ParameterMapping::direct("titleEncrypted", "title_encrypted"),
                ParameterMapping::direct("description", "description"),
                ParameterMapping::direct("descriptionEncrypted", "description_encrypted"),
                ParameterMapping::direct("priority", "priority"),
                ParameterMapping::direct("dueDate", "due_date"),
                ParameterMapping::direct("completed", "completed"),
                ParameterMapping::direct("tags", "tags"),
                ParameterMapping::direct("tagsEncrypted", "tags_encrypted"),
                ParameterMapping::direct("assignees", "assignees"),
            ],
        ),
        tool_spec(
            "rebelops_delete_task",
            "Delete a RebelOps task.",
            ToolOperation::Act,
            schema(vec![("taskId", integer_prop("Task ID"))], &["taskId"], None),
            Method::DELETE,
            "tasks/:taskId",
            Some("rebelops/tasks"),
            vec![ParameterMapping::direct("taskId", "taskId")],
            vec![],
            vec![],
        ),
        tool_spec(
            "rebelops_add_task_assignee",
            "Assign a user to a RebelOps task.",
            ToolOperation::Act,
            schema(
                vec![
                    ("taskId", integer_prop("Task ID")),
                    ("assigneeId", string_prop("Supabase user ID")),
                ],
                &["taskId", "assigneeId"],
                None,
            ),
            Method::POST,
            "tasks/:taskId/assignees",
            Some("rebelops/tasks"),
            vec![ParameterMapping::direct("taskId", "taskId")],
            vec![],
            vec![ParameterMapping::direct("assigneeId", "assignee_id")],
        ),
        tool_spec(
            "rebelops_replace_task_assignees",
            "Replace all assignees for a RebelOps task.",
            ToolOperation::Act,
            schema(
                vec![
                    ("taskId", integer_prop("Task ID")),
                    ("assignees", string_array_prop("Supabase user IDs")),
                ],
                &["taskId", "assignees"],
                None,
            ),
            Method::PUT,
            "tasks/:taskId/assignees",
            Some("rebelops/tasks"),
            vec![ParameterMapping::direct("taskId", "taskId")],
            vec![],
            vec![ParameterMapping::direct("assignees", "assignees")],
        ),
        tool_spec(
            "rebelops_remove_task_assignee",
            "Remove a single assignee from a RebelOps task.",
            ToolOperation::Act,
            schema(
                vec![
                    ("taskId", integer_prop("Task ID")),
                    ("assigneeId", string_prop("Supabase user ID")),
                ],
                &["taskId", "assigneeId"],
                None,
            ),
            Method::DELETE,
            "tasks/:taskId/assignees/:assigneeId",
            Some("rebelops/tasks"),
            vec![
                ParameterMapping::direct("taskId", "taskId"),
                ParameterMapping::direct("assigneeId", "assigneeId"),
            ],
            vec![],
            vec![],
        ),
    ]
}

fn decisions_specs() -> Vec<RebelOpsToolSpec> {
    vec![
        tool_spec(
            "rebelops_list_decisions",
            "List RebelOps decisions.",
            ToolOperation::Read,
            schema(
                vec![
                    ("extensionId", integer_prop("Decisions extension ID")),
                    ("projectId", integer_prop("Project ID")),
                ],
                &[],
                None,
            ),
            Method::GET,
            "decisions",
            Some("rebelops/decisions"),
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
            ],
            vec![],
        ),
        tool_spec(
            "rebelops_get_decision",
            "Fetch a single RebelOps decision.",
            ToolOperation::Read,
            schema(vec![("decisionId", integer_prop("Decision ID"))], &["decisionId"], None),
            Method::GET,
            "decisions/:decisionId",
            Some("rebelops/decisions"),
            vec![ParameterMapping::direct("decisionId", "decisionId")],
            vec![],
            vec![],
        ),
        tool_spec(
            "rebelops_list_project_decisions",
            "List RebelOps decisions for a project hierarchy.",
            ToolOperation::Read,
            schema(
                vec![
                    ("projectId", integer_prop("Project ID")),
                    ("extensionId", integer_prop("Decisions extension ID")),
                ],
                &["projectId"],
                None,
            ),
            Method::GET,
            "decisions/project/:projectId",
            Some("rebelops/decisions"),
            vec![ParameterMapping::direct("projectId", "projectId")],
            vec![ParameterMapping::extension("extensionId", "extension_id")],
            vec![],
        ),
        tool_spec(
            "rebelops_create_decision",
            "Create a RebelOps decision.",
            ToolOperation::Act,
            schema(
                vec![
                    ("extensionId", integer_prop("Decisions extension ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("title", string_prop("Decision title")),
                    ("titleEncrypted", string_prop("Encrypted decision title")),
                    ("description", string_prop("Decision description")),
                    ("descriptionEncrypted", string_prop("Encrypted decision description")),
                ],
                &["extensionId"],
                None,
            ),
            Method::POST,
            "decisions",
            Some("rebelops/decisions"),
            vec![],
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("title", "title"),
                ParameterMapping::direct("titleEncrypted", "title_encrypted"),
                ParameterMapping::direct("description", "description"),
                ParameterMapping::direct("descriptionEncrypted", "description_encrypted"),
            ],
        ),
        tool_spec(
            "rebelops_update_decision",
            "Update a RebelOps decision.",
            ToolOperation::Act,
            schema(
                vec![
                    ("decisionId", integer_prop("Decision ID")),
                    ("title", string_prop("Updated title")),
                    ("titleEncrypted", string_prop("Encrypted title")),
                    ("description", string_prop("Updated description")),
                    ("descriptionEncrypted", string_prop("Encrypted description")),
                ],
                &["decisionId"],
                None,
            ),
            Method::PUT,
            "decisions/:decisionId",
            Some("rebelops/decisions"),
            vec![ParameterMapping::direct("decisionId", "decisionId")],
            vec![],
            vec![
                ParameterMapping::direct("title", "title"),
                ParameterMapping::direct("titleEncrypted", "title_encrypted"),
                ParameterMapping::direct("description", "description"),
                ParameterMapping::direct("descriptionEncrypted", "description_encrypted"),
            ],
        ),
        tool_spec(
            "rebelops_delete_decision",
            "Delete a RebelOps decision.",
            ToolOperation::Act,
            schema(vec![("decisionId", integer_prop("Decision ID"))], &["decisionId"], None),
            Method::DELETE,
            "decisions/:decisionId",
            Some("rebelops/decisions"),
            vec![ParameterMapping::direct("decisionId", "decisionId")],
            vec![],
            vec![],
        ),
    ]
}

fn news_specs() -> Vec<RebelOpsToolSpec> {
    vec![
        tool_spec(
            "rebelops_list_news",
            "List RebelOps news posts.",
            ToolOperation::Read,
            schema(
                vec![
                    ("extensionId", integer_prop("News extension ID")),
                    ("projectId", integer_prop("Project ID")),
                ],
                &[],
                None,
            ),
            Method::GET,
            "news",
            Some("rebelops/news"),
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
            ],
            vec![],
        ),
        tool_spec(
            "rebelops_get_news_post",
            "Fetch a single RebelOps news post.",
            ToolOperation::Read,
            schema(vec![("newsId", integer_prop("News post ID"))], &["newsId"], None),
            Method::GET,
            "news/:newsId",
            Some("rebelops/news"),
            vec![ParameterMapping::direct("newsId", "newsId")],
            vec![],
            vec![],
        ),
        tool_spec(
            "rebelops_list_project_news",
            "List RebelOps news posts for a project hierarchy.",
            ToolOperation::Read,
            schema(
                vec![
                    ("projectId", integer_prop("Project ID")),
                    ("extensionId", integer_prop("News extension ID")),
                ],
                &["projectId"],
                None,
            ),
            Method::GET,
            "news/project/:projectId",
            Some("rebelops/news"),
            vec![ParameterMapping::direct("projectId", "projectId")],
            vec![ParameterMapping::extension("extensionId", "extension_id")],
            vec![],
        ),
        tool_spec(
            "rebelops_create_news_post",
            "Create a RebelOps news post.",
            ToolOperation::Act,
            schema(
                vec![
                    ("extensionId", integer_prop("News extension ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("title", string_prop("News title")),
                    ("titleEncrypted", string_prop("Encrypted title")),
                    ("summary", string_prop("Summary")),
                    ("summaryEncrypted", string_prop("Encrypted summary")),
                    ("body", string_prop("Body")),
                    ("bodyEncrypted", string_prop("Encrypted body")),
                    ("featuredImageFileId", string_prop("Featured image file ID")),
                    ("isPublished", boolean_prop("Publish state")),
                    ("publishedAt", datetime_prop("Publish time")),
                ],
                &["extensionId", "projectId"],
                Some(json!([
                    { "required": ["body"] },
                    { "required": ["bodyEncrypted"] }
                ])),
            ),
            Method::POST,
            "news",
            Some("rebelops/news"),
            vec![],
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("title", "title"),
                ParameterMapping::direct("titleEncrypted", "title_encrypted"),
                ParameterMapping::direct("summary", "summary"),
                ParameterMapping::direct("summaryEncrypted", "summary_encrypted"),
                ParameterMapping::direct("body", "body"),
                ParameterMapping::direct("bodyEncrypted", "body_encrypted"),
                ParameterMapping::direct("featuredImageFileId", "featured_image_file_id"),
                ParameterMapping::direct("isPublished", "is_published"),
                ParameterMapping::direct("publishedAt", "published_at"),
            ],
        ),
        tool_spec(
            "rebelops_update_news_post",
            "Update a RebelOps news post.",
            ToolOperation::Act,
            schema(
                vec![
                    ("newsId", integer_prop("News post ID")),
                    ("title", string_prop("Updated title")),
                    ("titleEncrypted", string_prop("Encrypted title")),
                    ("summary", string_prop("Updated summary")),
                    ("summaryEncrypted", string_prop("Encrypted summary")),
                    ("body", string_prop("Updated body")),
                    ("bodyEncrypted", string_prop("Encrypted body")),
                    ("featuredImageFileId", string_prop("Featured image file ID")),
                    ("isPublished", boolean_prop("Publish state")),
                    ("publishedAt", datetime_prop("Publish time")),
                ],
                &["newsId"],
                None,
            ),
            Method::PUT,
            "news/:newsId",
            Some("rebelops/news"),
            vec![ParameterMapping::direct("newsId", "newsId")],
            vec![],
            vec![
                ParameterMapping::direct("title", "title"),
                ParameterMapping::direct("titleEncrypted", "title_encrypted"),
                ParameterMapping::direct("summary", "summary"),
                ParameterMapping::direct("summaryEncrypted", "summary_encrypted"),
                ParameterMapping::direct("body", "body"),
                ParameterMapping::direct("bodyEncrypted", "body_encrypted"),
                ParameterMapping::direct("featuredImageFileId", "featured_image_file_id"),
                ParameterMapping::direct("isPublished", "is_published"),
                ParameterMapping::direct("publishedAt", "published_at"),
            ],
        ),
        tool_spec(
            "rebelops_delete_news_post",
            "Delete a RebelOps news post.",
            ToolOperation::Act,
            schema(vec![("newsId", integer_prop("News post ID"))], &["newsId"], None),
            Method::DELETE,
            "news/:newsId",
            Some("rebelops/news"),
            vec![ParameterMapping::direct("newsId", "newsId")],
            vec![],
            vec![],
        ),
        tool_spec(
            "rebelops_get_news_settings",
            "Get RebelOps news settings for a project.",
            ToolOperation::Read,
            schema(
                vec![
                    ("extensionId", integer_prop("News extension ID")),
                    ("projectId", integer_prop("Project ID")),
                ],
                &["extensionId", "projectId"],
                None,
            ),
            Method::GET,
            "news/:extensionId/settings",
            Some("rebelops/news"),
            vec![ParameterMapping::extension("extensionId", "extensionId")],
            vec![ParameterMapping::direct("projectId", "project_id")],
            vec![],
        ),
        tool_spec(
            "rebelops_update_news_settings",
            "Update RebelOps news settings for a project.",
            ToolOperation::Act,
            schema(
                vec![
                    ("extensionId", integer_prop("News extension ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("encryptContent", boolean_prop("Encrypt content")),
                ],
                &["extensionId", "projectId"],
                None,
            ),
            Method::PUT,
            "news/:extensionId/settings",
            Some("rebelops/news"),
            vec![ParameterMapping::extension("extensionId", "extensionId")],
            vec![],
            vec![
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("encryptContent", "encrypt_content"),
            ],
        ),
    ]
}

fn git_repository_specs() -> Vec<RebelOpsToolSpec> {
    vec![
        tool_spec(
            "rebelops_get_repository_settings",
            "Get RebelOps git repository settings for a project.",
            ToolOperation::Read,
            schema(
                vec![
                    ("extensionId", integer_prop("Git repository extension ID")),
                    ("projectId", integer_prop("Project ID")),
                ],
                &["extensionId", "projectId"],
                None,
            ),
            Method::GET,
            "repositories/:extensionId/settings",
            Some("rebelops/git-repository"),
            vec![ParameterMapping::extension("extensionId", "extensionId")],
            vec![ParameterMapping::direct("projectId", "project_id")],
            vec![],
        ),
        tool_spec(
            "rebelops_update_repository_settings",
            "Create or update RebelOps git repository settings.",
            ToolOperation::Act,
            schema(
                vec![
                    ("extensionId", integer_prop("Git repository extension ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("provider", string_prop("Provider")),
                    ("providerEncrypted", string_prop("Encrypted provider")),
                    ("repositoryUrl", string_prop("Repository URL")),
                    ("repositoryUrlEncrypted", string_prop("Encrypted repository URL")),
                    ("apiBaseUrl", string_prop("API base URL")),
                    ("apiBaseUrlEncrypted", string_prop("Encrypted API base URL")),
                    ("accessToken", string_prop("Access token")),
                    ("accessTokenEncrypted", string_prop("Encrypted access token")),
                ],
                &["extensionId", "projectId"],
                None,
            ),
            Method::PUT,
            "repositories/:extensionId/settings",
            Some("rebelops/git-repository"),
            vec![ParameterMapping::extension("extensionId", "extensionId")],
            vec![],
            vec![
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("provider", "provider"),
                ParameterMapping::direct("providerEncrypted", "provider_encrypted"),
                ParameterMapping::direct("repositoryUrl", "repository_url"),
                ParameterMapping::direct("repositoryUrlEncrypted", "repository_url_encrypted"),
                ParameterMapping::direct("apiBaseUrl", "api_base_url"),
                ParameterMapping::direct("apiBaseUrlEncrypted", "api_base_url_encrypted"),
                ParameterMapping::direct("accessToken", "access_token"),
                ParameterMapping::direct("accessTokenEncrypted", "access_token_encrypted"),
            ],
        ),
    ]
}

fn crm_specs() -> Vec<RebelOpsToolSpec> {
    vec![
        tool_spec(
            "rebelops_list_crm_profiles",
            "List RebelOps CRM profiles.",
            ToolOperation::Read,
            schema(
                vec![
                    ("extensionId", integer_prop("CRM extension ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("tagId", integer_prop("CRM tag ID")),
                    ("assigneeId", string_prop("Supabase assignee ID")),
                    ("search", string_prop("Search term")),
                ],
                &["extensionId", "projectId"],
                None,
            ),
            Method::GET,
            "crm/profiles",
            Some("rebelops/crm"),
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("tagId", "tag_id"),
                ParameterMapping::direct("assigneeId", "assignee_id"),
                ParameterMapping::direct("search", "search"),
            ],
            vec![],
        ),
        tool_spec(
            "rebelops_get_crm_profile",
            "Fetch a single RebelOps CRM profile.",
            ToolOperation::Read,
            schema(vec![("profileId", integer_prop("CRM profile ID"))], &["profileId"], None),
            Method::GET,
            "crm/profiles/:profileId",
            Some("rebelops/crm"),
            vec![ParameterMapping::direct("profileId", "profileId")],
            vec![],
            vec![],
        ),
        tool_spec(
            "rebelops_create_crm_profile",
            "Create a RebelOps CRM profile.",
            ToolOperation::Act,
            schema(
                vec![
                    ("extensionId", integer_prop("CRM extension ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("name", string_prop("Name")),
                    ("nameEncrypted", string_prop("Encrypted name")),
                    ("email", string_prop("Email")),
                    ("emailEncrypted", string_prop("Encrypted email")),
                    ("phone", string_prop("Phone")),
                    ("phoneEncrypted", string_prop("Encrypted phone")),
                    ("organization", string_prop("Organization")),
                    ("organizationEncrypted", string_prop("Encrypted organization")),
                    ("notes", string_prop("Notes")),
                    ("notesEncrypted", string_prop("Encrypted notes")),
                    ("avatarFileId", string_prop("Avatar file ID")),
                    ("tags", int_array_prop("CRM tag IDs")),
                    ("assignees", string_array_prop("Assignee user IDs")),
                    ("customFields", custom_fields_prop()),
                ],
                &["extensionId", "projectId"],
                None,
            ),
            Method::POST,
            "crm/profiles",
            Some("rebelops/crm"),
            vec![],
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("name", "name"),
                ParameterMapping::direct("nameEncrypted", "name_encrypted"),
                ParameterMapping::direct("email", "email"),
                ParameterMapping::direct("emailEncrypted", "email_encrypted"),
                ParameterMapping::direct("phone", "phone"),
                ParameterMapping::direct("phoneEncrypted", "phone_encrypted"),
                ParameterMapping::direct("organization", "organization"),
                ParameterMapping::direct("organizationEncrypted", "organization_encrypted"),
                ParameterMapping::direct("notes", "notes"),
                ParameterMapping::direct("notesEncrypted", "notes_encrypted"),
                ParameterMapping::direct("avatarFileId", "avatar_file_id"),
                ParameterMapping::direct("tags", "tags"),
                ParameterMapping::direct("assignees", "assignees"),
                ParameterMapping::custom_fields("customFields", "custom_fields"),
            ],
        ),
        tool_spec(
            "rebelops_update_crm_profile",
            "Update a RebelOps CRM profile.",
            ToolOperation::Act,
            schema(
                vec![
                    ("profileId", integer_prop("CRM profile ID")),
                    ("name", string_prop("Name")),
                    ("nameEncrypted", string_prop("Encrypted name")),
                    ("email", string_prop("Email")),
                    ("emailEncrypted", string_prop("Encrypted email")),
                    ("phone", string_prop("Phone")),
                    ("phoneEncrypted", string_prop("Encrypted phone")),
                    ("organization", string_prop("Organization")),
                    ("organizationEncrypted", string_prop("Encrypted organization")),
                    ("notes", string_prop("Notes")),
                    ("notesEncrypted", string_prop("Encrypted notes")),
                    ("avatarFileId", string_prop("Avatar file ID")),
                    ("tags", int_array_prop("CRM tag IDs")),
                    ("assignees", string_array_prop("Assignee user IDs")),
                    ("customFields", custom_fields_prop()),
                ],
                &["profileId"],
                None,
            ),
            Method::PUT,
            "crm/profiles/:profileId",
            Some("rebelops/crm"),
            vec![ParameterMapping::direct("profileId", "profileId")],
            vec![],
            vec![
                ParameterMapping::direct("name", "name"),
                ParameterMapping::direct("nameEncrypted", "name_encrypted"),
                ParameterMapping::direct("email", "email"),
                ParameterMapping::direct("emailEncrypted", "email_encrypted"),
                ParameterMapping::direct("phone", "phone"),
                ParameterMapping::direct("phoneEncrypted", "phone_encrypted"),
                ParameterMapping::direct("organization", "organization"),
                ParameterMapping::direct("organizationEncrypted", "organization_encrypted"),
                ParameterMapping::direct("notes", "notes"),
                ParameterMapping::direct("notesEncrypted", "notes_encrypted"),
                ParameterMapping::direct("avatarFileId", "avatar_file_id"),
                ParameterMapping::direct("tags", "tags"),
                ParameterMapping::direct("assignees", "assignees"),
                ParameterMapping::custom_fields("customFields", "custom_fields"),
            ],
        ),
        tool_spec(
            "rebelops_delete_crm_profile",
            "Delete a RebelOps CRM profile.",
            ToolOperation::Act,
            schema(vec![("profileId", integer_prop("CRM profile ID"))], &["profileId"], None),
            Method::DELETE,
            "crm/profiles/:profileId",
            Some("rebelops/crm"),
            vec![ParameterMapping::direct("profileId", "profileId")],
            vec![],
            vec![],
        ),
        tool_spec(
            "rebelops_list_crm_tags",
            "List RebelOps CRM tags.",
            ToolOperation::Read,
            schema(
                vec![
                    ("extensionId", integer_prop("CRM extension ID")),
                    ("projectId", integer_prop("Project ID")),
                ],
                &["extensionId", "projectId"],
                None,
            ),
            Method::GET,
            "crm/tags",
            Some("rebelops/crm"),
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
            ],
            vec![],
        ),
        tool_spec(
            "rebelops_create_crm_tag",
            "Create a RebelOps CRM tag.",
            ToolOperation::Act,
            schema(
                vec![
                    ("extensionId", integer_prop("CRM extension ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("name", string_prop("Tag name")),
                    ("nameEncrypted", string_prop("Encrypted tag name")),
                    ("color", string_prop("Tag color")),
                ],
                &["extensionId", "projectId", "name"],
                None,
            ),
            Method::POST,
            "crm/tags",
            Some("rebelops/crm"),
            vec![],
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("name", "name"),
                ParameterMapping::direct("nameEncrypted", "name_encrypted"),
                ParameterMapping::direct("color", "color"),
            ],
        ),
        tool_spec(
            "rebelops_update_crm_tag",
            "Update a RebelOps CRM tag.",
            ToolOperation::Act,
            schema(
                vec![
                    ("tagId", integer_prop("Tag ID")),
                    ("name", string_prop("Tag name")),
                    ("nameEncrypted", string_prop("Encrypted tag name")),
                    ("color", string_prop("Tag color")),
                ],
                &["tagId"],
                None,
            ),
            Method::PUT,
            "crm/tags/:tagId",
            Some("rebelops/crm"),
            vec![ParameterMapping::direct("tagId", "tagId")],
            vec![],
            vec![
                ParameterMapping::direct("name", "name"),
                ParameterMapping::direct("nameEncrypted", "name_encrypted"),
                ParameterMapping::direct("color", "color"),
            ],
        ),
        tool_spec(
            "rebelops_delete_crm_tag",
            "Delete a RebelOps CRM tag.",
            ToolOperation::Act,
            schema(vec![("tagId", integer_prop("Tag ID"))], &["tagId"], None),
            Method::DELETE,
            "crm/tags/:tagId",
            Some("rebelops/crm"),
            vec![ParameterMapping::direct("tagId", "tagId")],
            vec![],
            vec![],
        ),
        tool_spec(
            "rebelops_list_crm_custom_fields",
            "List RebelOps CRM custom fields.",
            ToolOperation::Read,
            schema(
                vec![
                    ("extensionId", integer_prop("CRM extension ID")),
                    ("projectId", integer_prop("Project ID")),
                ],
                &["extensionId", "projectId"],
                None,
            ),
            Method::GET,
            "crm/custom-fields",
            Some("rebelops/crm"),
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
            ],
            vec![],
        ),
        tool_spec(
            "rebelops_create_crm_custom_field",
            "Create a RebelOps CRM custom field.",
            ToolOperation::Act,
            schema(
                vec![
                    ("extensionId", integer_prop("CRM extension ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("fieldKey", string_prop("Field key")),
                    ("label", string_prop("Label")),
                    ("type", string_prop("Field type")),
                    ("optionsJson", object_prop("Options JSON")),
                    ("required", boolean_prop("Whether the field is required")),
                    ("isActive", boolean_prop("Whether the field is active")),
                ],
                &["extensionId", "projectId", "fieldKey", "label", "type"],
                None,
            ),
            Method::POST,
            "crm/custom-fields",
            Some("rebelops/crm"),
            vec![],
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("fieldKey", "field_key"),
                ParameterMapping::direct("label", "label"),
                ParameterMapping::direct("type", "type"),
                ParameterMapping::direct("optionsJson", "options_json"),
                ParameterMapping::direct("required", "required"),
                ParameterMapping::direct("isActive", "is_active"),
            ],
        ),
        tool_spec(
            "rebelops_update_crm_custom_field",
            "Update a RebelOps CRM custom field.",
            ToolOperation::Act,
            schema(
                vec![
                    ("customFieldId", integer_prop("Custom field ID")),
                    ("fieldKey", string_prop("Field key")),
                    ("label", string_prop("Label")),
                    ("type", string_prop("Field type")),
                    ("optionsJson", object_prop("Options JSON")),
                    ("required", boolean_prop("Whether the field is required")),
                    ("isActive", boolean_prop("Whether the field is active")),
                ],
                &["customFieldId"],
                None,
            ),
            Method::PUT,
            "crm/custom-fields/:customFieldId",
            Some("rebelops/crm"),
            vec![ParameterMapping::direct("customFieldId", "customFieldId")],
            vec![],
            vec![
                ParameterMapping::direct("fieldKey", "field_key"),
                ParameterMapping::direct("label", "label"),
                ParameterMapping::direct("type", "type"),
                ParameterMapping::direct("optionsJson", "options_json"),
                ParameterMapping::direct("required", "required"),
                ParameterMapping::direct("isActive", "is_active"),
            ],
        ),
        tool_spec(
            "rebelops_delete_crm_custom_field",
            "Delete a RebelOps CRM custom field.",
            ToolOperation::Act,
            schema(vec![("customFieldId", integer_prop("Custom field ID"))], &["customFieldId"], None),
            Method::DELETE,
            "crm/custom-fields/:customFieldId",
            Some("rebelops/crm"),
            vec![ParameterMapping::direct("customFieldId", "customFieldId")],
            vec![],
            vec![],
        ),
        tool_spec(
            "rebelops_list_crm_profile_files",
            "List files attached to a RebelOps CRM profile.",
            ToolOperation::Read,
            schema(vec![("profileId", integer_prop("CRM profile ID"))], &["profileId"], None),
            Method::GET,
            "crm/profiles/:profileId/files",
            Some("rebelops/crm"),
            vec![ParameterMapping::direct("profileId", "profileId")],
            vec![],
            vec![],
        ),
        tool_spec(
            "rebelops_attach_crm_profile_file",
            "Attach a file to a RebelOps CRM profile.",
            ToolOperation::Act,
            schema(
                vec![
                    ("profileId", integer_prop("CRM profile ID")),
                    ("fileId", string_prop("File ID")),
                ],
                &["profileId", "fileId"],
                None,
            ),
            Method::POST,
            "crm/profiles/:profileId/files",
            Some("rebelops/crm"),
            vec![ParameterMapping::direct("profileId", "profileId")],
            vec![],
            vec![ParameterMapping::direct("fileId", "file_id")],
        ),
        tool_spec(
            "rebelops_remove_crm_profile_file",
            "Remove a file from a RebelOps CRM profile.",
            ToolOperation::Act,
            schema(
                vec![
                    ("profileId", integer_prop("CRM profile ID")),
                    ("fileId", string_prop("File ID")),
                ],
                &["profileId", "fileId"],
                None,
            ),
            Method::DELETE,
            "crm/profiles/:profileId/files/:fileId",
            Some("rebelops/crm"),
            vec![
                ParameterMapping::direct("profileId", "profileId"),
                ParameterMapping::direct("fileId", "fileId"),
            ],
            vec![],
            vec![],
        ),
    ]
}

fn shifts_specs() -> Vec<RebelOpsToolSpec> {
    vec![
        tool_spec(
            "rebelops_list_shifts",
            "List RebelOps shifts.",
            ToolOperation::Read,
            schema(
                vec![
                    ("extensionId", integer_prop("Shifts extension ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("assignedTo", string_prop("Supabase user ID")),
                    ("startDate", datetime_prop("Start date")),
                    ("endDate", datetime_prop("End date")),
                ],
                &["extensionId"],
                None,
            ),
            Method::GET,
            "shifts",
            Some("rebelops/shifts"),
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("assignedTo", "assigned_to"),
                ParameterMapping::direct("startDate", "start_date"),
                ParameterMapping::direct("endDate", "end_date"),
            ],
            vec![],
        ),
        tool_spec(
            "rebelops_create_shift",
            "Create a RebelOps shift.",
            ToolOperation::Act,
            schema(
                vec![
                    ("extensionId", integer_prop("Shifts extension ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("title", string_prop("Shift title")),
                    ("titleEncrypted", string_prop("Encrypted shift title")),
                    ("description", string_prop("Shift description")),
                    ("descriptionEncrypted", string_prop("Encrypted shift description")),
                    ("startTime", datetime_prop("Start time")),
                    ("endTime", datetime_prop("End time")),
                    ("requirements", requirements_prop()),
                ],
                &["extensionId", "title", "startTime", "endTime"],
                None,
            ),
            Method::POST,
            "shifts",
            Some("rebelops/shifts"),
            vec![],
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("title", "title"),
                ParameterMapping::direct("titleEncrypted", "title_encrypted"),
                ParameterMapping::direct("description", "description"),
                ParameterMapping::direct("descriptionEncrypted", "description_encrypted"),
                ParameterMapping::direct("startTime", "start_time"),
                ParameterMapping::direct("endTime", "end_time"),
                ParameterMapping::requirements("requirements", "requirements"),
            ],
        ),
        tool_spec(
            "rebelops_delete_shift",
            "Delete a RebelOps shift.",
            ToolOperation::Act,
            schema(vec![("shiftId", integer_prop("Shift ID"))], &["shiftId"], None),
            Method::DELETE,
            "shifts/:shiftId",
            Some("rebelops/shifts"),
            vec![ParameterMapping::direct("shiftId", "shiftId")],
            vec![],
            vec![],
        ),
        tool_spec(
            "rebelops_list_shift_requirements",
            "List staffing requirements for a RebelOps shift.",
            ToolOperation::Read,
            schema(vec![("shiftId", integer_prop("Shift ID"))], &["shiftId"], None),
            Method::GET,
            "shifts/:shiftId/requirements",
            Some("rebelops/shifts"),
            vec![ParameterMapping::direct("shiftId", "shiftId")],
            vec![],
            vec![],
        ),
        tool_spec(
            "rebelops_replace_shift_requirements",
            "Replace staffing requirements for a RebelOps shift.",
            ToolOperation::Act,
            schema(
                vec![
                    ("shiftId", integer_prop("Shift ID")),
                    ("requirements", requirements_prop()),
                ],
                &["shiftId", "requirements"],
                None,
            ),
            Method::PUT,
            "shifts/:shiftId/requirements",
            Some("rebelops/shifts"),
            vec![ParameterMapping::direct("shiftId", "shiftId")],
            vec![],
            vec![ParameterMapping::requirements("requirements", "requirements")],
        ),
        tool_spec(
            "rebelops_list_staff_roles",
            "List RebelOps staff roles.",
            ToolOperation::Read,
            schema(vec![("projectId", integer_prop("Project ID"))], &["projectId"], None),
            Method::GET,
            "staff-roles",
            Some("rebelops/shifts"),
            vec![],
            vec![ParameterMapping::direct("projectId", "project_id")],
            vec![],
        ),
        tool_spec(
            "rebelops_create_staff_role",
            "Create a RebelOps staff role.",
            ToolOperation::Act,
            schema(
                vec![
                    ("projectId", integer_prop("Project ID")),
                    ("title", string_prop("Role title")),
                    ("titleEncrypted", string_prop("Encrypted role title")),
                ],
                &["projectId"],
                None,
            ),
            Method::POST,
            "staff-roles",
            Some("rebelops/shifts"),
            vec![],
            vec![],
            vec![
                ParameterMapping::direct("title", "title"),
                ParameterMapping::direct("titleEncrypted", "title_encrypted"),
                ParameterMapping::direct("projectId", "project_id"),
            ],
        ),
        tool_spec(
            "rebelops_update_staff_role",
            "Update a RebelOps staff role.",
            ToolOperation::Act,
            schema(
                vec![
                    ("roleId", integer_prop("Role ID")),
                    ("title", string_prop("Role title")),
                    ("titleEncrypted", string_prop("Encrypted role title")),
                ],
                &["roleId"],
                None,
            ),
            Method::PUT,
            "staff-roles/:roleId",
            Some("rebelops/shifts"),
            vec![ParameterMapping::direct("roleId", "roleId")],
            vec![],
            vec![
                ParameterMapping::direct("title", "title"),
                ParameterMapping::direct("titleEncrypted", "title_encrypted"),
            ],
        ),
        tool_spec(
            "rebelops_delete_staff_role",
            "Delete a RebelOps staff role.",
            ToolOperation::Act,
            schema(vec![("roleId", integer_prop("Role ID"))], &["roleId"], None),
            Method::DELETE,
            "staff-roles/:roleId",
            Some("rebelops/shifts"),
            vec![ParameterMapping::direct("roleId", "roleId")],
            vec![],
            vec![],
        ),
        tool_spec(
            "rebelops_list_staff_assignments",
            "List RebelOps staff assignments.",
            ToolOperation::Read,
            schema(
                vec![
                    ("roleId", integer_prop("Role ID")),
                    ("userId", string_prop("Supabase user ID")),
                    ("projectId", integer_prop("Project ID")),
                ],
                &[],
                None,
            ),
            Method::GET,
            "staff",
            Some("rebelops/shifts"),
            vec![],
            vec![
                ParameterMapping::direct("roleId", "role_id"),
                ParameterMapping::direct("userId", "user_id"),
                ParameterMapping::direct("projectId", "project_id"),
            ],
            vec![],
        ),
        tool_spec(
            "rebelops_assign_staff_role",
            "Assign a user to a RebelOps staff role.",
            ToolOperation::Act,
            schema(
                vec![
                    ("roleId", integer_prop("Role ID")),
                    ("userId", string_prop("Supabase user ID")),
                ],
                &["roleId", "userId"],
                None,
            ),
            Method::POST,
            "staff",
            Some("rebelops/shifts"),
            vec![],
            vec![],
            vec![
                ParameterMapping::direct("roleId", "role_id"),
                ParameterMapping::direct("userId", "user_id"),
            ],
        ),
        tool_spec(
            "rebelops_list_shift_exceptions",
            "List RebelOps shift exceptions.",
            ToolOperation::Read,
            schema(
                vec![
                    ("shiftId", integer_prop("Shift ID")),
                    ("roleId", integer_prop("Role ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("startDate", datetime_prop("Start date")),
                    ("endDate", datetime_prop("End date")),
                ],
                &[],
                None,
            ),
            Method::GET,
            "shift-exceptions",
            Some("rebelops/shifts"),
            vec![],
            vec![
                ParameterMapping::direct("shiftId", "shift_id"),
                ParameterMapping::direct("roleId", "role_id"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("startDate", "start_date"),
                ParameterMapping::direct("endDate", "end_date"),
            ],
            vec![],
        ),
        tool_spec(
            "rebelops_list_shift_assignments",
            "List RebelOps shift assignments.",
            ToolOperation::Read,
            schema(
                vec![
                    ("shiftId", integer_prop("Shift ID")),
                    ("staffId", integer_prop("Staff assignment ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("startDate", datetime_prop("Start date")),
                    ("endDate", datetime_prop("End date")),
                ],
                &[],
                None,
            ),
            Method::GET,
            "assignments",
            Some("rebelops/shifts"),
            vec![],
            vec![
                ParameterMapping::direct("shiftId", "shift_id"),
                ParameterMapping::direct("staffId", "staff_id"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("startDate", "start_date"),
                ParameterMapping::direct("endDate", "end_date"),
            ],
            vec![],
        ),
        tool_spec(
            "rebelops_create_shift_assignments",
            "Create RebelOps shift assignments.",
            ToolOperation::Act,
            schema(vec![("assignments", assignments_prop())], &["assignments"], None),
            Method::POST,
            "assignments",
            Some("rebelops/shifts"),
            vec![],
            vec![],
            vec![ParameterMapping::assignments("assignments", "assignments")],
        ),
        tool_spec(
            "rebelops_delete_shift_assignment",
            "Delete a RebelOps shift assignment.",
            ToolOperation::Act,
            schema(vec![("assignmentId", integer_prop("Assignment ID"))], &["assignmentId"], None),
            Method::DELETE,
            "assignments/:assignmentId",
            Some("rebelops/shifts"),
            vec![ParameterMapping::direct("assignmentId", "assignmentId")],
            vec![],
            vec![],
        ),
        tool_spec(
            "rebelops_list_shift_absences",
            "List RebelOps shift absences.",
            ToolOperation::Read,
            schema(vec![("projectId", integer_prop("Project ID"))], &[], None),
            Method::GET,
            "absences",
            Some("rebelops/shifts"),
            vec![],
            vec![ParameterMapping::direct("projectId", "project_id")],
            vec![],
        ),
        tool_spec(
            "rebelops_create_shift_absence",
            "Create a RebelOps shift absence.",
            ToolOperation::Act,
            schema(
                vec![
                    ("staffId", integer_prop("Staff ID")),
                    ("assignmentId", integer_prop("Assignment ID")),
                    ("reason", string_prop("Reason")),
                    ("reasonEncrypted", string_prop("Encrypted reason")),
                    ("status", string_prop("Status")),
                ],
                &["staffId", "assignmentId"],
                None,
            ),
            Method::POST,
            "absences",
            Some("rebelops/shifts"),
            vec![],
            vec![],
            vec![
                ParameterMapping::direct("staffId", "staff_id"),
                ParameterMapping::direct("assignmentId", "assignment_id"),
                ParameterMapping::direct("reason", "reason"),
                ParameterMapping::direct("reasonEncrypted", "reason_encrypted"),
                ParameterMapping::direct("status", "status"),
            ],
        ),
        tool_spec(
            "rebelops_update_shift_absence_status",
            "Update the status of a RebelOps shift absence.",
            ToolOperation::Act,
            schema(
                vec![
                    ("absenceId", integer_prop("Absence ID")),
                    ("status", string_prop("Status")),
                ],
                &["absenceId", "status"],
                None,
            ),
            Method::PUT,
            "absences/:absenceId/status",
            Some("rebelops/shifts"),
            vec![ParameterMapping::direct("absenceId", "absenceId")],
            vec![],
            vec![ParameterMapping::direct("status", "status")],
        ),
        tool_spec(
            "rebelops_delete_shift_absence",
            "Delete a RebelOps shift absence.",
            ToolOperation::Act,
            schema(vec![("absenceId", integer_prop("Absence ID"))], &["absenceId"], None),
            Method::DELETE,
            "absences/:absenceId",
            Some("rebelops/shifts"),
            vec![ParameterMapping::direct("absenceId", "absenceId")],
            vec![],
            vec![],
        ),
    ]
}

fn time_tracking_specs() -> Vec<RebelOpsToolSpec> {
    vec![
        tool_spec(
            "rebelops_list_time_entries",
            "List RebelOps time entries.",
            ToolOperation::Read,
            schema(
                vec![
                    ("projectId", integer_prop("Project ID")),
                    ("userId", string_prop("Supabase user ID")),
                    ("startDate", datetime_prop("Start date")),
                    ("endDate", datetime_prop("End date")),
                    ("includeSubprojects", boolean_prop("Include subprojects")),
                ],
                &[],
                None,
            ),
            Method::GET,
            "time-tracking/entries",
            Some("rebelops/time-tracking"),
            vec![],
            vec![
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("userId", "user_id"),
                ParameterMapping::direct("startDate", "start_date"),
                ParameterMapping::direct("endDate", "end_date"),
                ParameterMapping::direct("includeSubprojects", "include_subprojects"),
            ],
            vec![],
        ),
        tool_spec(
            "rebelops_create_time_entry",
            "Create a RebelOps time entry.",
            ToolOperation::Act,
            schema(
                vec![
                    ("extensionId", integer_prop("Time tracking extension ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("activity", string_prop("Activity")),
                    ("activityEncrypted", string_prop("Encrypted activity")),
                    ("notes", string_prop("Notes")),
                    ("notesEncrypted", string_prop("Encrypted notes")),
                    ("startTime", datetime_prop("Start time")),
                    ("endTime", datetime_prop("End time")),
                ],
                &["projectId", "startTime", "endTime"],
                None,
            ),
            Method::POST,
            "time-tracking/entries",
            Some("rebelops/time-tracking"),
            vec![],
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("activity", "activity"),
                ParameterMapping::direct("activityEncrypted", "activity_encrypted"),
                ParameterMapping::direct("notes", "notes"),
                ParameterMapping::direct("notesEncrypted", "notes_encrypted"),
                ParameterMapping::direct("startTime", "start_time"),
                ParameterMapping::direct("endTime", "end_time"),
            ],
        ),
        tool_spec(
            "rebelops_update_time_entry",
            "Update a RebelOps time entry.",
            ToolOperation::Act,
            schema(
                vec![
                    ("entryId", integer_prop("Entry ID")),
                    ("activity", string_prop("Activity")),
                    ("activityEncrypted", string_prop("Encrypted activity")),
                    ("notes", string_prop("Notes")),
                    ("notesEncrypted", string_prop("Encrypted notes")),
                    ("startTime", datetime_prop("Start time")),
                    ("endTime", datetime_prop("End time")),
                ],
                &["entryId", "startTime", "endTime"],
                None,
            ),
            Method::PUT,
            "time-tracking/entries/:entryId",
            Some("rebelops/time-tracking"),
            vec![ParameterMapping::direct("entryId", "entryId")],
            vec![],
            vec![
                ParameterMapping::direct("activity", "activity"),
                ParameterMapping::direct("activityEncrypted", "activity_encrypted"),
                ParameterMapping::direct("notes", "notes"),
                ParameterMapping::direct("notesEncrypted", "notes_encrypted"),
                ParameterMapping::direct("startTime", "start_time"),
                ParameterMapping::direct("endTime", "end_time"),
            ],
        ),
        tool_spec(
            "rebelops_get_active_time_session",
            "Get the active RebelOps time-tracking session.",
            ToolOperation::Read,
            schema(vec![("extensionId", integer_prop("Time tracking extension ID"))], &[], None),
            Method::GET,
            "time-tracking/sessions/active",
            Some("rebelops/time-tracking"),
            vec![],
            vec![ParameterMapping::extension("extensionId", "extension_id")],
            vec![],
        ),
        tool_spec(
            "rebelops_start_time_session",
            "Start a RebelOps time-tracking session.",
            ToolOperation::Act,
            schema(
                vec![
                    ("extensionId", integer_prop("Time tracking extension ID")),
                    ("projectId", integer_prop("Project ID")),
                    ("activity", string_prop("Activity")),
                    ("activityEncrypted", string_prop("Encrypted activity")),
                ],
                &["projectId"],
                None,
            ),
            Method::POST,
            "time-tracking/sessions/start",
            Some("rebelops/time-tracking"),
            vec![],
            vec![],
            vec![
                ParameterMapping::extension("extensionId", "extension_id"),
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("activity", "activity"),
                ParameterMapping::direct("activityEncrypted", "activity_encrypted"),
            ],
        ),
        tool_spec(
            "rebelops_heartbeat_time_session",
            "Send a heartbeat for a RebelOps time-tracking session.",
            ToolOperation::Act,
            schema(vec![("sessionId", integer_prop("Session ID"))], &[], None),
            Method::POST,
            "time-tracking/sessions/heartbeat",
            Some("rebelops/time-tracking"),
            vec![],
            vec![],
            vec![ParameterMapping::direct("sessionId", "session_id")],
        ),
        tool_spec(
            "rebelops_stop_time_session",
            "Stop a RebelOps time-tracking session.",
            ToolOperation::Act,
            schema(vec![("sessionId", integer_prop("Session ID"))], &[], None),
            Method::POST,
            "time-tracking/sessions/stop",
            Some("rebelops/time-tracking"),
            vec![],
            vec![],
            vec![ParameterMapping::direct("sessionId", "session_id")],
        ),
        tool_spec(
            "rebelops_list_recent_time_activities",
            "List recent RebelOps time-tracking activities.",
            ToolOperation::Read,
            schema(vec![("limit", integer_prop("Maximum activities to return"))], &[], None),
            Method::GET,
            "time-tracking/activities/recent",
            Some("rebelops/time-tracking"),
            vec![],
            vec![ParameterMapping::direct("limit", "limit")],
            vec![],
        ),
        tool_spec(
            "rebelops_get_time_tracking_report",
            "Get a RebelOps time-tracking report.",
            ToolOperation::Read,
            schema(
                vec![
                    ("projectId", integer_prop("Project ID")),
                    ("startDate", datetime_prop("Start date")),
                    ("endDate", datetime_prop("End date")),
                    ("includeSubprojects", boolean_prop("Include subprojects")),
                ],
                &["projectId"],
                None,
            ),
            Method::GET,
            "time-tracking/report",
            Some("rebelops/time-tracking"),
            vec![],
            vec![
                ParameterMapping::direct("projectId", "project_id"),
                ParameterMapping::direct("startDate", "start_date"),
                ParameterMapping::direct("endDate", "end_date"),
                ParameterMapping::direct("includeSubprojects", "include_subprojects"),
            ],
            vec![],
        ),
    ]
}
