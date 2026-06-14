//! Antigravity provider implementation
//!
//! Fetches usage data from Antigravity's local language server probe
//! Uses Windows process detection to find CSRF token

use async_trait::async_trait;
use regex_lite::Regex;
use serde::Deserialize;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::OnceLock;

use crate::core::{
    FetchContext, Provider, ProviderError, ProviderFetchResult, ProviderId, ProviderMetadata,
    RateWindow, SourceMode, UsageSnapshot,
};

/// Antigravity provider
pub struct AntigravityProvider {
    metadata: ProviderMetadata,
}

impl AntigravityProvider {
    pub fn new() -> Self {
        Self {
            metadata: ProviderMetadata {
                id: ProviderId::Antigravity,
                display_name: "Antigravity",
                session_label: "Gemini Models: Weekly Limit",
                weekly_label: "Gemini Models: Five Hour Limit",
                supports_opus: false,
                supports_credits: false,
                default_enabled: false,
                is_primary: false,
                dashboard_url: None,
                status_page_url: None,
            },
        }
    }

    /// Detect running Antigravity language server and extract connection info
    fn detect_process_info() -> Result<ProcessInfo, ProviderError> {
        // Use PowerShell to get process command lines
        #[cfg(windows)]
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let mut cmd = Command::new("powershell.exe");
        cmd.args([
                "-ExecutionPolicy", "Bypass",
                "-Command",
                "Get-CimInstance Win32_Process | Where-Object { $_.Name -like '*language_server_windows*' } | ForEach-Object { \"$($_.ProcessId)`t$($_.CommandLine)\" }"
            ]);
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);

        let output = cmd
            .output()
            .map_err(|e| ProviderError::Other(format!("Failed to run PowerShell: {}", e)))?;

        if !output.status.success() {
            return Err(ProviderError::NotInstalled(
                "Failed to detect Antigravity process".to_string(),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse command line for CSRF token and port — compiled once
        static CSRF_RE: OnceLock<Regex> = OnceLock::new();
        static EXT_CSRF_RE: OnceLock<Regex> = OnceLock::new();
        static PORT_RE: OnceLock<Regex> = OnceLock::new();
        let csrf_regex = CSRF_RE
            .get_or_init(|| Regex::new(r"--csrf_token\s+([a-f0-9-]+)").expect("valid regex"));
        let ext_csrf_regex = EXT_CSRF_RE.get_or_init(|| {
            Regex::new(r"--extension_server_csrf_token\s+([a-f0-9-]+)").expect("valid regex")
        });
        let port_regex = PORT_RE
            .get_or_init(|| Regex::new(r"--extension_server_port\s+(\d+)").expect("valid regex"));

        for line in stdout.lines() {
            if line.contains("language_server_windows") && line.contains("--csrf_token") {
                // Line is "<pid>\t<command line>"; split off the PID prefix we added so the
                // PID can be used to enumerate the process's real listening ports below.
                let (pid, line) = match line.split_once('\t') {
                    Some((p, rest)) => (p.trim().parse::<u32>().ok(), rest),
                    None => (None, line),
                };

                let csrf_token = csrf_regex
                    .captures(line)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string());

                let ext_csrf_token = ext_csrf_regex
                    .captures(line)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string());

                let port = port_regex
                    .captures(line)
                    .and_then(|c| c.get(1))
                    .and_then(|m| m.as_str().parse::<u16>().ok());

                if let (Some(token), Some(p)) = (csrf_token, port) {
                    return Ok(ProcessInfo {
                        csrf_token: token,
                        extension_server_csrf_token: ext_csrf_token,
                        extension_port: p,
                        pid,
                    });
                }
            }
        }

        Err(ProviderError::NotInstalled(
            "Antigravity language server not running".to_string(),
        ))
    }

    /// Find the actual API port by probing the language server's candidate ports.
    async fn find_api_port(extension_port: u16, pid: Option<u32>) -> Result<u16, ProviderError> {
        // The language server binds a RANDOM localhost port at startup; --extension_server_port
        // is only a reference point (and belongs to a separate HTTP extension server), so the
        // real gRPC/Connect API port is not guaranteed to be within a small window above it.
        // Mirror the macOS/Linux probe (which uses `lsof`) by enumerating the language-server
        // process's own listening ports first, then fall back to a heuristic window above the
        // extension port and a few historically-seen ports.
        //
        // SECURITY: TLS verification is disabled because the local language server uses a
        // self-signed certificate. This is scoped to 127.0.0.1 only; we confirm a port by
        // checking that it answers the expected gRPC endpoint.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ProviderError::Other(e.to_string()))?;

        // Ordered candidate ports: the process's real listening ports first (Windows
        // equivalent of `lsof`), then the heuristic window above the extension port, then a
        // few known ports as a last resort.
        let mut candidates: Vec<u16> = Vec::new();
        if let Some(pid) = pid {
            candidates.extend(Self::listening_ports_for_pid(pid));
        }
        candidates.extend((0..20u16).map(|offset| extension_port.saturating_add(offset)));
        candidates.extend([53835, 53836, 53837, 53838, 53845, 53849]);

        let mut probed: Vec<u16> = Vec::new();
        for port in candidates {
            if probed.contains(&port) {
                continue; // probe each port at most once
            }
            probed.push(port);
            if Self::probe_api_port(&client, port).await {
                return Ok(port);
            }
        }

        Err(ProviderError::Other(
            "Could not find Antigravity API port".to_string(),
        ))
    }

    /// Probe a single candidate port. Returns true if it answers the language server's
    /// gRPC endpoint (HTTP 200 or 401).
    async fn probe_api_port(client: &reqwest::Client, port: u16) -> bool {
        let url = format!(
            "https://127.0.0.1:{}/exa.language_server_pb.LanguageServerService/GetUnleashData",
            port
        );
        match client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Connect-Protocol-Version", "1")
            .body("{}")
            .send()
            .await
        {
            Ok(resp) => {
                let code = resp.status().as_u16();
                code == 200 || code == 401
            }
            Err(_) => false,
        }
    }

    /// Enumerate the TCP ports a given PID is listening on (Windows `lsof` equivalent).
    /// On Windows this uses `Get-NetTCPConnection`; it returns an empty list on any failure
    /// so the caller deterministically falls back to the heuristic candidate ports.
    #[cfg(windows)]
    fn listening_ports_for_pid(pid: u32) -> Vec<u16> {
        const CREATE_NO_WINDOW: u32 = 0x08000000;

        let mut cmd = Command::new("powershell.exe");
        cmd.args([
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &format!(
                "Get-NetTCPConnection -OwningProcess {pid} -State Listen \
                 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort"
            ),
        ]);
        cmd.creation_flags(CREATE_NO_WINDOW);

        let Ok(output) = cmd.output() else {
            return Vec::new();
        };
        if !output.status.success() {
            return Vec::new();
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut ports: Vec<u16> = stdout
            .lines()
            .filter_map(|l| l.trim().parse::<u16>().ok())
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Non-Windows platforms have no `Get-NetTCPConnection`; return an empty list by design so
    /// the caller falls back to the heuristic candidate ports.
    #[cfg(not(windows))]
    fn listening_ports_for_pid(_pid: u32) -> Vec<u16> {
        Vec::new()
    }

    /// Fetch user status from Antigravity API
    async fn fetch_user_status(&self) -> Result<UsageSnapshot, ProviderError> {
        let process_info = Self::detect_process_info()?;
        let api_port = Self::find_api_port(process_info.extension_port, process_info.pid).await?;

        // SECURITY: TLS verification disabled for local language server (see find_api_port)
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(8))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ProviderError::Other(e.to_string()))?;

        let url = format!(
            "https://127.0.0.1:{}/exa.language_server_pb.LanguageServerService/GetUserStatus",
            api_port
        );

        let body = serde_json::json!({
            "metadata": {
                "ideName": "antigravity",
                "extensionName": "antigravity",
                "ideVersion": "unknown",
                "locale": "en"
            }
        });

        // Use extension server CSRF token if available, otherwise fall back to language server token
        let csrf_token = process_info
            .extension_server_csrf_token
            .as_deref()
            .unwrap_or(&process_info.csrf_token);

        let resp = client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Connect-Protocol-Version", "1")
            .header("X-Codeium-Csrf-Token", csrf_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Other(format!("API request failed: {}", e)))?;

        if !resp.status().is_success() {
            // Retry with language server CSRF token if extension server token failed
            if process_info.extension_server_csrf_token.is_some() {
                let retry_resp = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .header("Connect-Protocol-Version", "1")
                    .header("X-Codeium-Csrf-Token", &process_info.csrf_token)
                    .json(&body)
                    .send()
                    .await;

                if let Ok(retry) = retry_resp
                    && retry.status().is_success()
                {
                    let raw_val: serde_json::Value = retry
                        .json()
                        .await
                        .map_err(|e| ProviderError::Parse(e.to_string()))?;
                    let json: UserStatusResponse = serde_json::from_value(raw_val)
                        .map_err(|e| ProviderError::Parse(e.to_string()))?;
                    return self.parse_user_status(json);
                }
            }

            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Other(format!(
                "API error {}: {}",
                status, text
            )));
        }

        let raw_val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ProviderError::Other(format!("Failed to parse response: {}", e)))?;

        let json: UserStatusResponse = serde_json::from_value(raw_val)
            .map_err(|e| ProviderError::Other(format!("Failed to parse response: {}", e)))?;

        self.parse_user_status(json)
    }

    fn parse_user_status(
        &self,
        response: UserStatusResponse,
    ) -> Result<UsageSnapshot, ProviderError> {
        let user_status = response
            .user_status
            .ok_or_else(|| ProviderError::Other("Missing userStatus".to_string()))?;

        let model_configs = user_status
            .cascade_model_config_data
            .and_then(|d| d.client_model_configs)
            .unwrap_or_default();

        let mut gemini_weekly: Option<QuotaInfo> = None;
        let mut gemini_five_hour: Option<QuotaInfo> = None;
        let mut claude_weekly: Option<QuotaInfo> = None;
        let mut claude_five_hour: Option<QuotaInfo> = None;

        for config in model_configs {
            let Some(quota) = &config.quota_info else {
                continue;
            };
            let label = model_label(&config);
            if label.is_empty() {
                continue;
            }

            let is_gemini = label.to_lowercase().contains("gemini");
            let is_weekly = label.to_lowercase().contains("(low)");

            let target = if is_gemini {
                if is_weekly {
                    &mut gemini_weekly
                } else {
                    &mut gemini_five_hour
                }
            } else {
                if is_weekly {
                    &mut claude_weekly
                } else {
                    &mut claude_five_hour
                }
            };

            // Keep the one with the minimum remaining_fraction (most restrictive)
            if let Some(existing) = target {
                let existing_rem = existing.remaining_fraction.unwrap_or(1.0);
                let new_rem = quota.remaining_fraction.unwrap_or(1.0);
                if new_rem < existing_rem {
                    *existing = quota.clone();
                }
            } else {
                *target = Some(quota.clone());
            }
        }

        let primary = rate_window_from_quota_opt(gemini_weekly.as_ref());
        let secondary = rate_window_from_quota_opt(gemini_five_hour.as_ref());

        let mut snapshot = UsageSnapshot::new(primary).with_secondary(secondary);

        let claude_weekly_win = rate_window_from_quota_opt(claude_weekly.as_ref());
        let claude_five_hour_win = rate_window_from_quota_opt(claude_five_hour.as_ref());

        snapshot = snapshot.with_extra_rate_window(
            "claude-gpt-weekly",
            "Claude & GPT Models: Weekly Limit",
            claude_weekly_win,
        );
        snapshot = snapshot.with_extra_rate_window(
            "claude-gpt-five-hour",
            "Claude & GPT Models: Five Hour Limit",
            claude_five_hour_win,
        );

        // Add plan info
        let plan_name = user_status
            .plan_status
            .and_then(|ps| ps.plan_info)
            .and_then(|pi| pi.plan_display_name.or(pi.plan_name));

        if let Some(plan) = plan_name {
            snapshot = snapshot.with_login_method(&plan);
        }

        if let Some(ref email) = user_status.email {
            snapshot = snapshot.with_email(email);
        }

        Ok(snapshot)
    }
}

impl Default for AntigravityProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Provider for AntigravityProvider {
    fn id(&self) -> ProviderId {
        ProviderId::Antigravity
    }

    fn metadata(&self) -> &ProviderMetadata {
        &self.metadata
    }

    async fn fetch_usage(&self, _ctx: &FetchContext) -> Result<ProviderFetchResult, ProviderError> {
        tracing::debug!("Fetching Antigravity usage via local probe");

        match self.fetch_user_status().await {
            Ok(usage) => Ok(ProviderFetchResult::new(usage, "local")),
            Err(e) => {
                tracing::warn!("Antigravity probe failed: {}", e);
                Err(e)
            }
        }
    }

    fn available_sources(&self) -> Vec<SourceMode> {
        vec![SourceMode::Auto, SourceMode::Cli]
    }

    fn supports_cli(&self) -> bool {
        true
    }
}

struct ProcessInfo {
    csrf_token: String,
    extension_server_csrf_token: Option<String>,
    extension_port: u16,
    pid: Option<u32>,
}

// API Response types

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserStatusResponse {
    user_status: Option<UserStatus>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserStatus {
    email: Option<String>,
    plan_status: Option<PlanStatus>,
    cascade_model_config_data: Option<ModelConfigData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlanStatus {
    plan_info: Option<PlanInfo>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlanInfo {
    plan_name: Option<String>,
    plan_display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ModelConfigData {
    client_model_configs: Option<Vec<ModelConfig>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ModelConfig {
    #[serde(default)]
    label: String,
    #[serde(default)]
    model_id: Option<String>,
    #[serde(default)]
    id: Option<String>,
    quota_info: Option<QuotaInfo>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct QuotaInfo {
    remaining_fraction: Option<f64>,
    reset_time: Option<String>,
}

fn model_label(config: &ModelConfig) -> &str {
    if !config.label.trim().is_empty() {
        &config.label
    } else if let Some(model_id) = config.model_id.as_deref() {
        model_id
    } else {
        config.id.as_deref().unwrap_or_default()
    }
}

fn rate_window_from_quota_opt(quota: Option<&QuotaInfo>) -> RateWindow {
    match quota {
        Some(q) => {
            let remaining = q.remaining_fraction.unwrap_or(1.0);
            let used_percent = (1.0 - remaining) * 100.0;
            RateWindow::with_details(used_percent, None, None, q.reset_time.clone())
        }
        None => RateWindow::new(0.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_response(models: Vec<(&str, f64)>) -> UserStatusResponse {
        let json = serde_json::json!({
            "userStatus": {
                "cascadeModelConfigData": {
                    "clientModelConfigs": models.iter().map(|(label, remaining)| {
                        serde_json::json!({
                            "label": label,
                            "quotaInfo": {
                                "remainingFraction": remaining
                            }
                        })
                    }).collect::<Vec<_>>()
                }
            }
        });
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn test_parse_user_status_grouped() {
        let resp = make_response(vec![
            ("Gemini 3.5 Flash (High)", 0.5),
            ("Gemini 3.5 Flash (Low)", 0.6),
            ("Gemini 3.1 Pro (Low)", 0.7),
            ("Gemini 3.1 Pro (High)", 0.55),
            ("Claude Sonnet 4.6 (Thinking)", 0.8),
            ("Claude Opus 4.6 (Thinking)", 0.9),
            ("GPT-OSS 120B (Medium)", 0.85),
            ("Gemini 3.5 Flash (Medium)", 0.4),
        ]);
        let provider = AntigravityProvider::new();
        let snap = provider.parse_user_status(resp).unwrap();

        // Gemini Weekly: lowest of Gemini low configs (0.6, 0.7) -> 0.6. used = (1 - 0.6) * 100 = 40%
        assert!((snap.primary.used_percent - 40.0).abs() < 0.1);

        // Gemini Five Hour: lowest of Gemini high/medium configs (0.5, 0.55, 0.4) -> 0.4. used = (1 - 0.4) * 100 = 60%
        let sec = snap.secondary.unwrap();
        assert!((sec.used_percent - 60.0).abs() < 0.1);

        // Claude & GPT Weekly: none matched -> default 0% used
        let extra_weekly = snap
            .extra_rate_windows
            .iter()
            .find(|w| w.id == "claude-gpt-weekly")
            .unwrap();
        assert!((extra_weekly.window.used_percent - 0.0).abs() < 0.1);

        // Claude & GPT Five Hour: lowest of (0.8, 0.9, 0.85) -> 0.8. used = (1 - 0.8) * 100 = 20%
        let extra_five_hour = snap
            .extra_rate_windows
            .iter()
            .find(|w| w.id == "claude-gpt-five-hour")
            .unwrap();
        assert!((extra_five_hour.window.used_percent - 20.0).abs() < 0.1);
    }
}
