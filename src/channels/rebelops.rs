use super::traits::{Channel, ChannelMessage, SendMessage};
use crate::config::schema::RebelOpsConfig;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as WsMessage;

const AUTH_REFRESH_SKEW_MS: u64 = 30_000;
const LINKED_ORGANIZATIONS_TTL_MS: u64 = 5 * 60 * 1000;
const ORGANIZATION_PROBE_TTL_MS: u64 = 60 * 1000;
const DISCOVERY_INTERVAL_SECS: u64 = 60;
const RECONNECT_DELAY_SECS: u64 = 10;
const PING_INTERVAL_SECS: u64 = 30;
const PROCESSED_MESSAGE_TTL_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone)]
struct AuthSession {
    access_token: String,
    user_id: String,
    expires_at_ms: u64,
}

#[derive(Debug, Clone)]
struct LinkedOrganization {
    slug: String,
    organization_url: String,
}

#[derive(Debug, Clone)]
struct CachedOrganizations {
    organizations: Vec<LinkedOrganization>,
    expires_at_ms: u64,
}

#[derive(Debug, Default)]
struct ChannelCaches {
    auth_session: Option<AuthSession>,
    linked_organizations: Option<CachedOrganizations>,
    organization_probe_checked_at: HashMap<String, u64>,
    processed_message_ids: HashMap<String, u64>,
}

#[derive(Debug, Deserialize)]
struct SupabasePasswordGrantResponse {
    access_token: Option<String>,
    expires_at: Option<u64>,
    expires_in: Option<u64>,
    user: Option<SupabasePasswordGrantUser>,
}

#[derive(Debug, Deserialize)]
struct SupabasePasswordGrantUser {
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AccountLinkedOrganizationRow {
    organization_id: Option<String>,
    organizations: Option<AccountLinkedOrganization>,
}

#[derive(Debug, Deserialize)]
struct AccountLinkedOrganization {
    id: Option<String>,
    slug: Option<String>,
    deleted_at: Option<String>,
    platform_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RebelOpsSendResponse {
    message: Option<RebelOpsSendResponseMessage>,
}

#[derive(Debug, Deserialize)]
struct RebelOpsSendResponseMessage {
    id: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RebelOpsReplyContext {
    original_message_id: String,
    sender_id: Option<String>,
}

pub struct RebelOpsChannel {
    config: RebelOpsConfig,
    client: reqwest::Client,
    caches: Arc<Mutex<ChannelCaches>>,
}

impl RebelOpsChannel {
    pub fn new(config: RebelOpsConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
            caches: Arc::new(Mutex::new(ChannelCaches::default())),
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.config.timeout_ms.max(1_000))
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn retain_recent_processed_messages(
        processed_message_ids: &mut HashMap<String, u64>,
        now_ms: u64,
    ) {
        processed_message_ids
            .retain(|_, seen_at_ms| now_ms.saturating_sub(*seen_at_ms) < PROCESSED_MESSAGE_TTL_MS);
    }

    fn normalize_project_id(raw: Option<&str>) -> Option<String> {
        let value = raw?.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
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

    fn build_organization_api_url(&self, organization_url: &str) -> Result<reqwest::Url> {
        let mut url = reqwest::Url::parse(organization_url)
            .with_context(|| format!("Invalid RebelOps organization URL: {organization_url}"))?;
        let path_prefix = if self.config.api_base_path.starts_with('/') {
            self.config.api_base_path.clone()
        } else {
            format!("/{}", self.config.api_base_path)
        };
        url.set_path(&path_prefix);
        url.set_query(None);
        Ok(url)
    }

    fn build_project_messages_url(
        &self,
        organization_url: &str,
        project_id: &str,
    ) -> Result<reqwest::Url> {
        let mut url = reqwest::Url::parse(organization_url)
            .with_context(|| format!("Invalid RebelOps organization URL: {organization_url}"))?;
        let path_prefix = if self.config.api_base_path.starts_with('/') {
            self.config.api_base_path.trim_end_matches('/').to_string()
        } else {
            format!("/{}", self.config.api_base_path.trim_matches('/'))
        };
        url.set_path(&format!("{path_prefix}/projects/{project_id}/messages"));
        url.set_query(None);
        Ok(url)
    }

    fn build_ws_url(&self, organization_url: &str) -> Result<reqwest::Url> {
        let mut url = reqwest::Url::parse(organization_url)
            .with_context(|| format!("Invalid RebelOps organization URL: {organization_url}"))?;
        match url.scheme() {
            "https" => {
                url.set_scheme("wss")
                    .map_err(|_| anyhow!("Failed to switch RebelOps websocket URL to wss"))?;
            }
            "http" => {
                url.set_scheme("ws")
                    .map_err(|_| anyhow!("Failed to switch RebelOps websocket URL to ws"))?;
            }
            _ => bail!(
                "Unsupported RebelOps organization URL scheme: {}",
                url.scheme()
            ),
        }
        url.set_path("/ws/projects");
        url.set_query(None);
        Ok(url)
    }

    fn parse_outbound_target(raw: &str) -> (Option<String>, Option<String>) {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return (None, None);
        }

        if let Some(rest) = trimmed.strip_prefix("organization:") {
            if let Some((slug, project_id)) = rest.split_once("/project:") {
                return (
                    Some(slug.trim().to_ascii_lowercase()),
                    Self::normalize_project_id(Some(project_id)),
                );
            }
        }

        if let Some((left, right)) = trimmed.split_once('/') {
            if !left.trim().is_empty() && !right.trim().is_empty() {
                return (
                    Some(left.trim().to_ascii_lowercase()),
                    Self::normalize_project_id(Some(right)),
                );
            }
        }

        if let Some((left, right)) = trimmed.split_once(':') {
            if !left.eq_ignore_ascii_case("project")
                && !left.trim().is_empty()
                && !right.trim().is_empty()
            {
                return (
                    Some(left.trim().to_ascii_lowercase()),
                    Self::normalize_project_id(Some(right)),
                );
            }
        }

        if let Some(project_id) = trimmed.strip_prefix("project:") {
            return (None, Self::normalize_project_id(Some(project_id)));
        }

        if let Some(project_id) = trimmed.strip_prefix("projects/") {
            return (None, Self::normalize_project_id(Some(project_id)));
        }

        (None, Self::normalize_project_id(Some(trimmed)))
    }

    fn build_reply_context(message_id: &str, sender_id: &str) -> String {
        format!("rebelops-reply:{message_id}|sender:{sender_id}")
    }

    fn parse_reply_context(raw: Option<&str>) -> Option<RebelOpsReplyContext> {
        let raw = raw?.trim();
        if raw.is_empty() {
            return None;
        }

        if let Some(rest) = raw.strip_prefix("rebelops-reply:") {
            let (original_message_id, sender_id) = match rest.split_once("|sender:") {
                Some((message_id, sender_id)) => (message_id.trim(), Some(sender_id.trim())),
                None => (rest.trim(), None),
            };
            if original_message_id.is_empty() {
                return None;
            }

            let sender_id = sender_id
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            return Some(RebelOpsReplyContext {
                original_message_id: original_message_id.to_string(),
                sender_id,
            });
        }

        Some(RebelOpsReplyContext {
            original_message_id: raw.to_string(),
            sender_id: None,
        })
    }

    fn build_reference_host(organization: &LinkedOrganization) -> Option<String> {
        if let Ok(url) = reqwest::Url::parse(&organization.organization_url) {
            if let Some(host) = url
                .host_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                if host.ends_with(".rebelops.app") {
                    return Some(host.to_string());
                }
            }
        }

        let slug = organization.slug.trim();
        if slug.is_empty() {
            return None;
        }

        Some(format!("{}.rebelops.app", slug))
    }

    fn build_message_reference_tag(
        organization: &LinkedOrganization,
        original_message_id: &str,
    ) -> Option<String> {
        let host = Self::build_reference_host(organization)?;
        if host.is_empty() {
            return None;
        }

        Some(format!("[ref:{host}:chat_messages:{original_message_id}]"))
    }

    fn build_outbound_message_text(
        organization: &LinkedOrganization,
        reply_context: Option<&RebelOpsReplyContext>,
        text: &str,
    ) -> String {
        let mut parts = Vec::new();
        if let Some(context) = reply_context {
            if let Some(reference_tag) =
                Self::build_message_reference_tag(organization, &context.original_message_id)
            {
                parts.push(reference_tag);
            }
            if let Some(sender_id) = context.sender_id.as_deref() {
                parts.push(format!("@user:{sender_id}"));
            }
        }
        parts.push(text.trim().to_string());
        parts.join(" ")
    }

    fn build_outbound_mentions(reply_context: Option<&RebelOpsReplyContext>) -> Vec<String> {
        reply_context
            .and_then(|context| context.sender_id.as_ref())
            .map(|sender_id| vec![sender_id.clone()])
            .unwrap_or_default()
    }

    fn normalize_ai_marker(ai: Option<&str>) -> Option<String> {
        match ai.map(str::trim) {
            Some(value) if !value.is_empty() => Some(value.to_string()),
            _ => None,
        }
    }

    fn normalize_inbound_message_text(
        &self,
        bot_user_id: &str,
        message_text: &str,
    ) -> Option<String> {
        let trimmed = message_text.trim();
        if trimmed.is_empty() {
            return None;
        }

        let mention_prefix = format!("@user:{bot_user_id}");
        let remainder = trimmed.strip_prefix(&mention_prefix)?;
        if let Some(next_char) = remainder.chars().next() {
            if !next_char.is_whitespace() && !matches!(next_char, ':' | ',' | ';' | '-') {
                return None;
            }
        }

        let normalized = remainder
            .trim_start_matches(|character: char| {
                character.is_whitespace() || matches!(character, ':' | ',' | ';' | '-')
            })
            .trim();
        if normalized.is_empty() {
            None
        } else {
            Some(normalized.to_string())
        }
    }

    fn try_claim_processed_message(&self, key: &str) -> bool {
        let mut caches = self
            .caches
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let now_ms = Self::now_ms();
        Self::retain_recent_processed_messages(&mut caches.processed_message_ids, now_ms);
        if caches.processed_message_ids.contains_key(key) {
            return false;
        }
        caches.processed_message_ids.insert(key.to_string(), now_ms);
        true
    }

    fn release_processed_message_claim(&self, key: &str) {
        let mut caches = self
            .caches
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        caches.processed_message_ids.remove(key);
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

    async fn get_auth_session(&self) -> Result<AuthSession> {
        {
            let caches = self.caches.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(session) = caches.auth_session.as_ref() {
                if session.expires_at_ms > Self::now_ms() + AUTH_REFRESH_SKEW_MS {
                    return Ok(session.clone());
                }
            }
        }

        let username = self
            .config
            .username
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .context("RebelOps channel username is not configured")?;
        let password = self
            .config
            .password
            .as_ref()
            .filter(|value| !value.trim().is_empty())
            .context("RebelOps channel password is not configured")?;

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
            .json(&serde_json::json!({
                "email": username,
                "password": password,
            }))
            .send()
            .await
            .context("Failed to sign in to RebelOps via Supabase")?;

        if !response.status().is_success() {
            bail!(
                "RebelOps sign-in failed: {}",
                Self::read_json_error_body(response).await
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
        let user_id = payload
            .user
            .and_then(|user| user.id)
            .filter(|value| !value.trim().is_empty())
            .context("RebelOps sign-in succeeded but user.id was missing")?;
        let expires_at_ms = payload
            .expires_at
            .map(|value| value.saturating_mul(1000))
            .or_else(|| {
                payload
                    .expires_in
                    .map(|value| Self::now_ms().saturating_add(value.saturating_mul(1000)))
            })
            .unwrap_or_else(|| Self::now_ms().saturating_add(60 * 60 * 1000));

        let session = AuthSession {
            access_token,
            user_id,
            expires_at_ms,
        };

        let mut caches = self.caches.lock().unwrap_or_else(|e| e.into_inner());
        caches.auth_session = Some(session.clone());
        Ok(session)
    }

    async fn authenticate_ws_stream<S>(
        &self,
        ws_stream: &mut tokio_tungstenite::WebSocketStream<S>,
        access_token: &str,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let auth_payload = serde_json::json!({
            "type": "auth",
            "token": access_token,
        })
        .to_string();
        ws_stream
            .send(WsMessage::Text(auth_payload.into()))
            .await
            .context("Failed to send RebelOps websocket auth payload")?;

        let auth_result = tokio::time::timeout(self.timeout(), async {
            while let Some(frame) = ws_stream.next().await {
                let frame = frame?;
                let Some(text) = ws_message_text(&frame) else {
                    continue;
                };
                let payload: Value = match serde_json::from_str(text) {
                    Ok(payload) => payload,
                    Err(_) => continue,
                };
                match payload.get("type").and_then(Value::as_str) {
                    Some("auth_success") => return Ok::<(), anyhow::Error>(()),
                    Some("auth_error") => {
                        let error = payload
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("authentication failed");
                        bail!("{error}");
                    }
                    _ => continue,
                }
            }

            bail!("RebelOps websocket closed before auth completed")
        })
        .await;

        match auth_result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error),
            Err(_) => bail!("RebelOps websocket auth timed out"),
        }
    }

    async fn send_typing_state(&self, recipient: &str, is_typing: bool) -> Result<()> {
        let (requested_slug, requested_project_id) = Self::parse_outbound_target(recipient);
        let project_id =
            requested_project_id.context("RebelOps typing indication requires a project id")?;

        let session = self.get_auth_session().await?;
        let organization = self
            .resolve_target_organization(&session, requested_slug.as_deref())
            .await?;

        let ws_url = self.build_ws_url(&organization.organization_url)?;
        let (mut ws_stream, _) = connect_async(ws_url.as_str())
            .await
            .context("Failed to connect to RebelOps websocket for typing indication")?;
        self.authenticate_ws_stream(&mut ws_stream, &session.access_token)
            .await?;

        let typing_payload = serde_json::json!({
            "type": "typing_indication",
            "data": {
                "project_id": project_id,
                "is_typing": is_typing,
                "supabase_user_id": session.user_id,
            }
        })
        .to_string();

        ws_stream
            .send(WsMessage::Text(typing_payload.into()))
            .await
            .context("Failed to send RebelOps typing indication")?;
        let _ = ws_stream.close(None).await;
        Ok(())
    }

    async fn list_linked_organizations(
        &self,
        session: &AuthSession,
        force_refresh: bool,
    ) -> Result<Vec<LinkedOrganization>> {
        if !force_refresh {
            let caches = self.caches.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(cached) = caches.linked_organizations.as_ref() {
                if cached.expires_at_ms > Self::now_ms() {
                    return Ok(cached.organizations.clone());
                }
            }
        }

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
                Self::read_json_error_body(response).await
            );
        }

        let rows: Vec<AccountLinkedOrganizationRow> = response
            .json()
            .await
            .context("Failed to parse linked RebelOps organizations response")?;

        let mut organizations = Vec::new();
        for row in rows {
            let Some(details) = row.organizations else {
                continue;
            };
            if details.deleted_at.is_some() {
                continue;
            }
            let Some(slug) = details
                .slug
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            let platform_url = details
                .platform_url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let organization_url = if let Some(platform_url) = platform_url {
                platform_url.trim_end_matches('/').to_string()
            } else {
                format!("https://{}.rebelops.app", slug.to_ascii_lowercase())
            };
            let _organization_id = details.id.or(row.organization_id);
            organizations.push(LinkedOrganization {
                slug: slug.to_ascii_lowercase(),
                organization_url,
            });
        }

        let mut caches = self.caches.lock().unwrap_or_else(|e| e.into_inner());
        caches.linked_organizations = Some(CachedOrganizations {
            organizations: organizations.clone(),
            expires_at_ms: Self::now_ms().saturating_add(LINKED_ORGANIZATIONS_TTL_MS),
        });
        Ok(organizations)
    }

    async fn ensure_organization_api_reachable(
        &self,
        session: &AuthSession,
        organization: &LinkedOrganization,
    ) -> Result<()> {
        {
            let caches = self.caches.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(checked_at) = caches
                .organization_probe_checked_at
                .get(&organization.organization_url)
            {
                if *checked_at + ORGANIZATION_PROBE_TTL_MS > Self::now_ms() {
                    return Ok(());
                }
            }
        }

        let response = self
            .client
            .get(self.build_organization_api_url(&organization.organization_url)?)
            .header("authorization", format!("Bearer {}", session.access_token))
            .header("content-type", "application/json")
            .timeout(self.timeout())
            .send()
            .await
            .with_context(|| {
                format!(
                    "Failed to reach RebelOps organization {}",
                    organization.slug
                )
            })?;

        match response.status() {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                bail!(
                    "Bot access to RebelOps organization {} appears to have been revoked or is no longer valid",
                    organization.slug
                );
            }
            StatusCode::NOT_FOUND => {
                bail!(
                    "RebelOps organization {} is unavailable or no longer exists at {}",
                    organization.slug,
                    organization.organization_url
                );
            }
            _ => {}
        }

        if !response.status().is_success() {
            bail!(
                "Failed to reach RebelOps organization {}: {}",
                organization.slug,
                Self::read_json_error_body(response).await
            );
        }

        let spec: Value = response
            .json()
            .await
            .context("Failed to parse RebelOps organization API response")?;
        let has_messages_path = spec
            .get("paths")
            .and_then(Value::as_object)
            .map(|paths| paths.contains_key("/api/projects/{projectId}/messages"))
            .unwrap_or(false);
        if !has_messages_path {
            bail!(
                "RebelOps organization {} does not expose the project message endpoint for this bot account",
                organization.slug
            );
        }

        let mut caches = self.caches.lock().unwrap_or_else(|e| e.into_inner());
        caches
            .organization_probe_checked_at
            .insert(organization.organization_url.clone(), Self::now_ms());
        Ok(())
    }

    async fn resolve_target_organization(
        &self,
        session: &AuthSession,
        requested_slug: Option<&str>,
    ) -> Result<LinkedOrganization> {
        let requested_slug = requested_slug
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_ascii_lowercase());

        let linked = self.list_linked_organizations(session, false).await?;

        if let Some(slug) = requested_slug {
            if let Some(matched) = linked.iter().find(|organization| organization.slug == slug) {
                return Ok(matched.clone());
            }

            bail!(
                "RebelOps organization {} is not currently linked to this bot account, may have been deleted, or access may have been revoked",
                slug
            );
        }

        match linked.as_slice() {
            [organization] => Ok(organization.clone()),
            [] => bail!(
                "This RebelOps bot account does not currently have any linked organizations available"
            ),
            _ => bail!(
                "This RebelOps bot account is linked to multiple organizations. Specify the target as <organization-slug>/<project-id>"
            ),
        }
    }

    async fn handle_inbound_message(
        &self,
        tx: &mpsc::Sender<ChannelMessage>,
        organization: &LinkedOrganization,
        session_user_id: &str,
        payload: &Value,
    ) -> Result<()> {
        let Some(data) = payload.get("data") else {
            return Ok(());
        };

        let project_id = data
            .get("projectId")
            .or_else(|| data.get("project_id"))
            .and_then(value_to_string);
        let Some(project_id) = project_id.filter(|value| !value.is_empty()) else {
            return Ok(());
        };

        let Some(message) = data.get("message") else {
            return Ok(());
        };
        let message_id = message.get("id").and_then(value_to_string);
        let Some(message_id) = message_id.filter(|value| !value.is_empty()) else {
            return Ok(());
        };

        let sender_id = message
            .get("supabase_user_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let Some(sender_id) = sender_id else {
            return Ok(());
        };

        if sender_id == session_user_id {
            return Ok(());
        }

        let message_type = message
            .get("message_type")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("user_message");
        if message_type != "user_message" {
            return Ok(());
        }

        let message_text = message
            .get("message_text")
            .and_then(Value::as_str)
            .map(|value| value.replace("\r\n", "\n"))
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if message_text.is_none()
            && message
                .get("message_text_encrypted")
                .and_then(Value::as_str)
                .map(str::trim)
                .is_some_and(|value| !value.is_empty())
        {
            tracing::info!(
                "RebelOps: skipping encrypted-only inbound message {} from {}/{}",
                message_id,
                organization.slug,
                project_id
            );
        }
        let Some(message_text) = message_text else {
            return Ok(());
        };
        let normalized_message_text =
            self.normalize_inbound_message_text(session_user_id, &message_text);
        let channel_name = if normalized_message_text.is_some() {
            "rebelops"
        } else {
            "rebelops:passive"
        };
        let message_text = normalized_message_text.unwrap_or(message_text);

        let dedupe_key = format!("{}:{}:{}", organization.slug, project_id, message_id);
        if !self.try_claim_processed_message(&dedupe_key) {
            tracing::debug!(
                "RebelOps: skipping duplicate inbound message {} for {}/{}",
                message_id,
                organization.slug,
                project_id
            );
            return Ok(());
        }

        let timestamp = message
            .get("created_at")
            .and_then(Value::as_str)
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.timestamp().max(0) as u64)
            .unwrap_or_else(|| Self::now_ms() / 1000);
        let reply_context = Self::build_reply_context(&message_id, &sender_id);

        let send_result = tx
            .send(ChannelMessage {
                id: message_id,
                sender: sender_id,
                reply_target: format!("{}/{}", organization.slug, project_id),
                content: message_text,
                channel: channel_name.to_string(),
                timestamp,
                thread_ts: Some(reply_context),
                interruption_scope_id: None,
                attachments: vec![],
            })
            .await;

        if let Err(error) = send_result {
            self.release_processed_message_claim(&dedupe_key);
            return Err(error).context("Failed to forward inbound RebelOps message");
        }

        Ok(())
    }

    async fn run_organization_socket(
        self: Arc<Self>,
        organization: LinkedOrganization,
        tx: mpsc::Sender<ChannelMessage>,
        cancellation: tokio_util::sync::CancellationToken,
    ) {
        while !cancellation.is_cancelled() && !tx.is_closed() {
            let session = match self.get_auth_session().await {
                Ok(session) => session,
                Err(error) => {
                    tracing::warn!(
                        "RebelOps monitor for {} failed to refresh auth: {}",
                        organization.slug,
                        error
                    );
                    tokio::select! {
                        _ = cancellation.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(RECONNECT_DELAY_SECS)) => {}
                    }
                    continue;
                }
            };

            if let Err(error) = self
                .ensure_organization_api_reachable(&session, &organization)
                .await
            {
                tracing::warn!(
                    "RebelOps monitor for {} failed API probe: {}",
                    organization.slug,
                    error
                );
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(RECONNECT_DELAY_SECS)) => {}
                }
                continue;
            }

            let ws_url = match self.build_ws_url(&organization.organization_url) {
                Ok(url) => url,
                Err(error) => {
                    tracing::warn!(
                        "RebelOps monitor for {} has invalid websocket URL: {}",
                        organization.slug,
                        error
                    );
                    break;
                }
            };

            let connection = connect_async(ws_url.as_str()).await;
            let (mut ws_stream, _) = match connection {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!(
                        "RebelOps websocket connect failed for {}: {}",
                        organization.slug,
                        error
                    );
                    tokio::select! {
                        _ = cancellation.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(RECONNECT_DELAY_SECS)) => {}
                    }
                    continue;
                }
            };

            match self
                .authenticate_ws_stream(&mut ws_stream, &session.access_token)
                .await
            {
                Ok(()) => {
                    tracing::info!(
                        "RebelOps websocket connected for organization {}",
                        organization.slug
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        "RebelOps websocket auth failed for {}: {}",
                        organization.slug,
                        error
                    );
                    tokio::select! {
                        _ = cancellation.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(RECONNECT_DELAY_SECS)) => {}
                    }
                    continue;
                }
            }

            let (mut write, mut read) = ws_stream.split();

            let mut ping_interval = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
            ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            let mut disconnected = false;
            while !cancellation.is_cancelled() && !tx.is_closed() {
                tokio::select! {
                    _ = cancellation.cancelled() => {
                        let _ = write.close().await;
                        return;
                    }
                    _ = ping_interval.tick() => {
                        if let Err(error) = write.send(WsMessage::Text("{\"type\":\"ping\"}".to_string().into())).await {
                            tracing::warn!(
                                "RebelOps websocket ping failed for {}: {}",
                                organization.slug,
                                error
                            );
                            disconnected = true;
                            break;
                        }
                    }
                    frame = read.next() => {
                        match frame {
                            Some(Ok(frame)) => {
                                let Some(text) = ws_message_text(&frame) else {
                                    continue;
                                };
                                let payload: Value = match serde_json::from_str(text) {
                                    Ok(payload) => payload,
                                    Err(error) => {
                                        tracing::debug!(
                                            "RebelOps websocket payload parse failed for {}: {}",
                                            organization.slug,
                                            error
                                        );
                                        continue;
                                    }
                                };

                                if payload.get("type").and_then(Value::as_str) != Some("message_created") {
                                    continue;
                                }

                                if let Err(error) = self
                                    .handle_inbound_message(&tx, &organization, &session.user_id, &payload)
                                    .await
                                {
                                    tracing::warn!(
                                        "RebelOps inbound message handling failed for {}: {}",
                                        organization.slug,
                                        error
                                    );
                                }
                            }
                            Some(Err(error)) => {
                                tracing::warn!(
                                    "RebelOps websocket read failed for {}: {}",
                                    organization.slug,
                                    error
                                );
                                disconnected = true;
                                break;
                            }
                            None => {
                                disconnected = true;
                                break;
                            }
                        }
                    }
                }
            }

            if tx.is_closed() || cancellation.is_cancelled() {
                let _ = write.close().await;
                break;
            }

            if disconnected {
                tracing::warn!(
                    "RebelOps websocket disconnected for organization {}; reconnecting",
                    organization.slug
                );
            }

            tokio::select! {
                _ = cancellation.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(RECONNECT_DELAY_SECS)) => {}
            }
        }
    }
}

#[async_trait]
impl Channel for RebelOpsChannel {
    fn name(&self) -> &str {
        "rebelops"
    }

    async fn send(&self, message: &SendMessage) -> Result<()> {
        let text = message.content.trim();
        if text.is_empty() {
            bail!("RebelOps outbound text cannot be empty");
        }

        let (requested_slug, requested_project_id) =
            Self::parse_outbound_target(&message.recipient);
        let project_id = requested_project_id.context(
            "RebelOps channel requires a target project id. Use <organization-slug>/<project-id>",
        )?;

        let session = self.get_auth_session().await?;
        let organization = self
            .resolve_target_organization(&session, requested_slug.as_deref())
            .await?;
        self.ensure_organization_api_reachable(&session, &organization)
            .await?;
        let reply_context = Self::parse_reply_context(message.thread_ts.as_deref());
        let outbound_text =
            Self::build_outbound_message_text(&organization, reply_context.as_ref(), text);
        let outbound_mentions = Self::build_outbound_mentions(reply_context.as_ref());

        let response = self
            .client
            .post(self.build_project_messages_url(&organization.organization_url, &project_id)?)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", session.access_token))
            .timeout(self.timeout())
            .json(&serde_json::json!({
                "message_text": outbound_text,
                "supabase_user_id": session.user_id,
                "ai": Self::normalize_ai_marker(message.subject.as_deref()),
                "mentions": outbound_mentions,
            }))
            .send()
            .await
            .context("Failed to send message to RebelOps")?;

        if !response.status().is_success() {
            bail!(
                "RebelOps send failed: {}",
                Self::read_json_error_body(response).await
            );
        }

        let payload: RebelOpsSendResponse = response
            .json()
            .await
            .context("Failed to parse RebelOps send response")?;
        let Some(message_id) = payload
            .message
            .and_then(|message| message.id)
            .and_then(|value| value_to_string(&value))
        else {
            bail!("RebelOps send succeeded but response did not include message.id");
        };

        tracing::debug!(
            "RebelOps message sent to {}/{} with message id {}",
            organization.slug,
            project_id,
            message_id
        );
        Ok(())
    }

    async fn listen(&self, tx: mpsc::Sender<ChannelMessage>) -> Result<()> {
        tracing::info!("RebelOps channel active; monitoring linked organizations");
        let shared = Arc::new(Self {
            config: self.config.clone(),
            client: self.client.clone(),
            caches: Arc::clone(&self.caches),
        });
        let mut monitors: HashMap<
            String,
            (
                tokio_util::sync::CancellationToken,
                tokio::task::JoinHandle<()>,
            ),
        > = HashMap::new();

        loop {
            if tx.is_closed() {
                for (_, (cancellation, handle)) in monitors.drain() {
                    cancellation.cancel();
                    handle.abort();
                }
                return Ok(());
            }

            match shared.get_auth_session().await {
                Ok(session) => match shared.list_linked_organizations(&session, true).await {
                    Ok(organizations) => {
                        let next_slugs: HashSet<String> = organizations
                            .iter()
                            .map(|organization| organization.slug.clone())
                            .collect();

                        let stale_slugs: Vec<String> = monitors
                            .iter()
                            .filter_map(|(slug, (_, handle))| {
                                if !next_slugs.contains(slug) || handle.is_finished() {
                                    Some(slug.clone())
                                } else {
                                    None
                                }
                            })
                            .collect();

                        for slug in stale_slugs {
                            if let Some((cancellation, handle)) = monitors.remove(&slug) {
                                cancellation.cancel();
                                handle.abort();
                            }
                        }

                        for organization in organizations {
                            if monitors.contains_key(&organization.slug) {
                                continue;
                            }

                            let cancellation = tokio_util::sync::CancellationToken::new();
                            let task = tokio::spawn(shared.clone().run_organization_socket(
                                organization.clone(),
                                tx.clone(),
                                cancellation.clone(),
                            ));
                            monitors.insert(organization.slug.clone(), (cancellation, task));
                        }

                        if monitors.is_empty() {
                            tracing::warn!(
                                "RebelOps channel has no linked organizations available for this bot account"
                            );
                        }
                    }
                    Err(error) => {
                        tracing::warn!("RebelOps organization discovery failed: {}", error);
                    }
                },
                Err(error) => {
                    tracing::warn!("RebelOps auth refresh failed: {}", error);
                }
            }

            tokio::time::sleep(Duration::from_secs(DISCOVERY_INTERVAL_SECS)).await;
        }
    }

    async fn health_check(&self) -> bool {
        let session = match self.get_auth_session().await {
            Ok(session) => session,
            Err(error) => {
                tracing::debug!("RebelOps health check auth failed: {}", error);
                return false;
            }
        };

        let organizations = match self.list_linked_organizations(&session, false).await {
            Ok(organizations) => organizations,
            Err(error) => {
                tracing::debug!("RebelOps health check discovery failed: {}", error);
                return false;
            }
        };

        let Some(first_organization) = organizations.first() else {
            return false;
        };

        self.ensure_organization_api_reachable(&session, first_organization)
            .await
            .is_ok()
    }

    async fn start_typing(&self, recipient: &str) -> Result<()> {
        self.send_typing_state(recipient, true).await
    }

    async fn stop_typing(&self, recipient: &str) -> Result<()> {
        self.send_typing_state(recipient, false).await
    }
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.trim().to_string()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn ws_message_text(frame: &WsMessage) -> Option<&str> {
    match frame {
        WsMessage::Text(text) => Some(text.as_str()),
        WsMessage::Binary(bytes) => std::str::from_utf8(bytes).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::RebelOpsChannel;

    #[test]
    fn parse_outbound_target_supports_slug_and_project() {
        let (slug, project_id) = RebelOpsChannel::parse_outbound_target("alpha-org/42");
        assert_eq!(slug.as_deref(), Some("alpha-org"));
        assert_eq!(project_id.as_deref(), Some("42"));
    }

    #[test]
    fn parse_outbound_target_supports_project_prefix() {
        let (slug, project_id) = RebelOpsChannel::parse_outbound_target("project:17");
        assert!(slug.is_none());
        assert_eq!(project_id.as_deref(), Some("17"));
    }

    #[test]
    fn mention_requires_exact_bot_prefix() {
        let channel = RebelOpsChannel::new(crate::config::schema::RebelOpsConfig::default());
        let normalized = channel.normalize_inbound_message_text(
            "bot-123",
            "@user:bot-123 please summarize this thread",
        );
        assert_eq!(normalized.as_deref(), Some("please summarize this thread"));
        assert!(channel
            .normalize_inbound_message_text("bot-123", "please summarize this thread")
            .is_none());
    }

    #[test]
    fn mention_rejects_partial_prefix_match() {
        let channel = RebelOpsChannel::new(crate::config::schema::RebelOpsConfig::default());
        assert!(channel
            .normalize_inbound_message_text("bot-123", "@user:bot-1234 please summarize")
            .is_none());
    }

    #[test]
    fn reply_context_round_trips_message_and_sender() {
        let encoded = RebelOpsChannel::build_reply_context("42", "user-123");
        let decoded = RebelOpsChannel::parse_reply_context(Some(&encoded));
        assert_eq!(
            decoded,
            Some(super::RebelOpsReplyContext {
                original_message_id: "42".into(),
                sender_id: Some("user-123".into()),
            })
        );
    }

    #[test]
    fn outbound_message_text_includes_reference_and_sender_mention() {
        let reply_context = super::RebelOpsReplyContext {
            original_message_id: "42".into(),
            sender_id: Some("user-123".into()),
        };
        let organization = super::LinkedOrganization {
            slug: "alpha-org".into(),
            organization_url: "https://alpha-org.rebelops.app".into(),
        };

        let outbound = RebelOpsChannel::build_outbound_message_text(
            &organization,
            Some(&reply_context),
            "Thanks, I checked that.",
        );

        assert_eq!(
            outbound,
            "[ref:alpha-org.rebelops.app:chat_messages:42] @user:user-123 Thanks, I checked that."
        );
        assert_eq!(
            RebelOpsChannel::build_outbound_mentions(Some(&reply_context)),
            vec!["user-123".to_string()]
        );
    }

    #[test]
    fn outbound_message_text_uses_reference_without_sender_when_missing() {
        let reply_context = super::RebelOpsReplyContext {
            original_message_id: "77".into(),
            sender_id: None,
        };
        let organization = super::LinkedOrganization {
            slug: "alpha-org".into(),
            organization_url: "https://alpha-org.rebelops.app".into(),
        };

        let outbound = RebelOpsChannel::build_outbound_message_text(
            &organization,
            Some(&reply_context),
            "Status update",
        );

        assert_eq!(
            outbound,
            "[ref:alpha-org.rebelops.app:chat_messages:77] Status update"
        );
        assert!(RebelOpsChannel::build_outbound_mentions(Some(&reply_context)).is_empty());
    }

    #[test]
    fn normalize_ai_marker_trims_and_drops_empty_values() {
        assert_eq!(
            RebelOpsChannel::normalize_ai_marker(Some("  openai/gpt-5-mini  ")),
            Some("openai/gpt-5-mini".to_string())
        );
        assert_eq!(RebelOpsChannel::normalize_ai_marker(Some("   ")), None);
        assert_eq!(RebelOpsChannel::normalize_ai_marker(None), None);
    }

    #[test]
    fn reference_host_falls_back_to_public_rebelops_domain() {
        let organization = super::LinkedOrganization {
            slug: "alpha-org".into(),
            organization_url:
                "https://org-065b0ed8-e57c-4b7f-89e7-3fb1-rebelops-9dc02168.koyeb.app".into(),
        };

        assert_eq!(
            RebelOpsChannel::build_reference_host(&organization).as_deref(),
            Some("alpha-org.rebelops.app")
        );
        assert_eq!(
            RebelOpsChannel::build_message_reference_tag(&organization, "229").as_deref(),
            Some("[ref:alpha-org.rebelops.app:chat_messages:229]")
        );
    }
}
