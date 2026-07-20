// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for tools/extensions/plugins/MCP dispatch and
// tool-approval gating -- split out of the former monolithic state.rs (issue
// modularization pass) so this business entity's runtime logic lives in one
// place.

use super::*;
use ferrogate_mcp::McpDispatchHeaders;

impl AppState {
    pub(crate) fn extension_statuses(&self) -> Vec<ExtensionStatus> {
        self.extension_registry.statuses()
    }

    pub(crate) fn plugin_status(&self, id: &str) -> Option<ExtensionStatus> {
        self.extension_registry
            .statuses()
            .into_iter()
            .find(|status| status.id == id)
    }

    pub(crate) fn plugin_tools(&self, id: &str) -> Vec<RegisteredTool> {
        self.extension_registry.tools_for_plugin(id)
    }

    pub(crate) fn tenant_refs(&self) -> Vec<crate::responses::AdminTenantRef> {
        self.config
            .api_keys
            .iter()
            .filter(|key| {
                key.organization_id.is_some()
                    || key.team_id.is_some()
                    || key.project_id.is_some()
                    || key.user_id.is_some()
            })
            .map(|key| crate::responses::AdminTenantRef {
                organization_id: key.organization_id.clone(),
                team_id: key.team_id.clone(),
                project_id: key.project_id.clone(),
                user_id: key.user_id.clone(),
                api_key_id: key.id.clone(),
            })
            .collect()
    }

    pub(crate) fn tools_for(
        &self,
        tenant: &ferrogate_core::TenantContext,
        api_key_id: Option<&str>,
        route: Option<&str>,
    ) -> Vec<RegisteredTool> {
        let mut tools = self.extension_registry.tools_for(tenant, api_key_id, route);
        tools.extend(self.mcp_registered_tools());
        tools
    }

    pub(crate) fn mcp_tools_for(
        &self,
        tenant: &ferrogate_core::TenantContext,
        api_key_id: Option<&str>,
        route: Option<&str>,
    ) -> Vec<RegisteredTool> {
        self.tools_for(tenant, api_key_id, route)
            .into_iter()
            .filter(|tool| tool.extension_id.starts_with("mcp."))
            .collect()
    }

    pub(crate) fn all_tools(&self) -> Vec<RegisteredTool> {
        let mut tools = self.extension_registry.all_tools();
        tools.extend(self.mcp_registered_tools());
        tools
    }

    pub(crate) fn tool_by_name(&self, name: &str) -> Option<RegisteredTool> {
        self.extension_registry
            .all_tools()
            .into_iter()
            .find(|tool| tool.name == name)
            .or_else(|| self.mcp_registered_tool_by_name(name))
            // Built-in gateway tools (issue #257, e.g. `fetch_asset`) are
            // resolvable by the governed chokepoint's allowlist check exactly
            // like extension and MCP tools.
            .or_else(|| crate::builtin_tools::builtin_tool_by_name(name))
    }

    pub(crate) fn tool_approvals(&self) -> Vec<ToolApprovalRecord> {
        self.repositories
            .control_plane_tool_approvals()
            .map(|documents| deserialize_control_plane_documents(documents).unwrap_or_default())
            .unwrap_or_else(|_| self.approvals.list())
    }

    pub(crate) fn tool_approval(&self, id: &str) -> Option<ToolApprovalRecord> {
        self.repositories
            .control_plane_tool_approval(id)
            .ok()
            .flatten()
            .and_then(|document| serde_json::from_str(&document).ok())
            .or_else(|| self.approvals.get(id))
    }

    pub(crate) fn create_tool_approval(
        &self,
        request: ToolApprovalCreateRequest<'_>,
    ) -> anyhow::Result<ToolApprovalRecord> {
        let record = self.approvals.create_pending(ToolApprovalDraft {
            request_id: request.request_id.to_string(),
            trace_id: request.trace_id,
            agent_run_id: request.agent_run_id,
            workflow_id: request.workflow_id,
            workflow_node_id: request.workflow_node_id,
            action_fingerprint: request.action_fingerprint,
            tenant: request.tenant,
            actor_api_key_id: request.actor_api_key_id,
            tool_name: request.tool.name.clone(),
            server_name: request.server_name,
            route: request.tool.route.clone(),
            approval_policy: request.approval_policy,
            approval_timeout_secs: self.config.reliability.tool_approval_timeout_secs,
            config_snapshot: config_snapshot_id(&self.config),
            arguments: request.tool.arguments.clone(),
            can_log_bodies: request.can_log_bodies,
        });
        self.persist_tool_approval(&record)?;
        Ok(record)
    }

    pub(crate) async fn wait_for_tool_approval(
        &self,
        approval: &ToolApprovalRecord,
    ) -> Result<ToolApprovalRecord, ToolExecutionError> {
        let timeout = Duration::from_secs(approval.approval_timeout_secs.max(1));
        match self
            .approvals
            .wait_for_resolution(&approval.id, timeout)
            .await
        {
            Ok(record) if record.status == ApprovalStatus::Approved => {
                self.persist_tool_approval_as_tool_result(&record)?;
                Ok(record)
            }
            Ok(record) => {
                self.persist_tool_approval_as_tool_result(&record)?;
                Err(ToolExecutionError::Denied(format!(
                    "tool approval {} ended with status {:?}",
                    record.id, record.status
                )))
            }
            Err(ApprovalWaitError::NotFound(message)) => Err(ToolExecutionError::Denied(message)),
        }
    }

    pub(crate) fn approve_tool_approval(
        &self,
        id: &str,
        payload: ToolApprovalDecisionRequest,
        reviewer_api_key_id: Option<String>,
    ) -> Result<ToolApprovalRecord, ApprovalDecisionError> {
        let fingerprint = payload
            .fingerprint
            .as_deref()
            .unwrap_or_default()
            .to_string();
        match self
            .approvals
            .approve(id, &fingerprint, reviewer_api_key_id, payload.reason)
        {
            Ok(record) => {
                self.persist_tool_approval_as_decision(&record)?;
                Ok(record)
            }
            Err(error) => {
                if let Some(record) = self.approvals.get(id) {
                    self.persist_tool_approval_as_decision(&record)?;
                }
                Err(error)
            }
        }
    }
    pub(crate) fn deny_tool_approval(
        &self,
        id: &str,
        payload: ToolApprovalDecisionRequest,
        reviewer_api_key_id: Option<String>,
    ) -> Result<ToolApprovalRecord, ApprovalDecisionError> {
        match self.approvals.deny(id, reviewer_api_key_id, payload.reason) {
            Ok(record) => {
                self.persist_tool_approval_as_decision(&record)?;
                Ok(record)
            }
            Err(error) => {
                if let Some(record) = self.approvals.get(id) {
                    self.persist_tool_approval_as_decision(&record)?;
                }
                Err(error)
            }
        }
    }

    pub(crate) fn expire_tool_approval(
        &self,
        id: &str,
        payload: ToolApprovalDecisionRequest,
        reviewer_api_key_id: Option<String>,
    ) -> Result<ToolApprovalRecord, ApprovalDecisionError> {
        match self
            .approvals
            .expire(id, reviewer_api_key_id, payload.reason)
        {
            Ok(record) => {
                self.persist_tool_approval_as_decision(&record)?;
                Ok(record)
            }
            Err(error) => {
                if let Some(record) = self.approvals.get(id) {
                    self.persist_tool_approval_as_decision(&record)?;
                }
                Err(error)
            }
        }
    }

    fn persist_tool_approval(&self, record: &ToolApprovalRecord) -> anyhow::Result<()> {
        self.repositories.upsert_control_plane_tool_approval(
            record.id.clone(),
            serde_json::to_string(record)?,
        )?;
        Ok(())
    }

    fn persist_tool_approval_as_decision(
        &self,
        record: &ToolApprovalRecord,
    ) -> Result<(), ApprovalDecisionError> {
        self.persist_tool_approval(record).map_err(|error| {
            ApprovalDecisionError::NotFound(format!(
                "failed to persist tool approval {}: {error}",
                record.id
            ))
        })
    }

    fn persist_tool_approval_as_tool_result(
        &self,
        record: &ToolApprovalRecord,
    ) -> Result<(), ToolExecutionError> {
        self.persist_tool_approval(record)
            .map_err(|error| ToolExecutionError::Denied(error.to_string()))
    }

    pub(crate) fn mcp_statuses(&self) -> Vec<McpServerStatus> {
        self.mcp_manager.statuses()
    }

    pub(crate) fn mcp_health_check_and_reconnect(&self) {
        self.mcp_manager.health_check_and_reconnect();
    }

    fn mcp_registered_tools(&self) -> Vec<RegisteredTool> {
        self.mcp_manager
            .tools()
            .into_iter()
            .map(|tool| RegisteredTool {
                name: tool.name,
                description: tool.description,
                input_schema: tool.input_schema,
                extension_id: format!("mcp.{}", tool.server_name),
                approval_policy: tool.approval_policy,
                tenant_allowlist: Vec::new(),
                api_key_allowlist: Vec::new(),
                route_allowlist: Vec::new(),
            })
            .collect()
    }

    fn mcp_registered_tool_by_name(&self, name: &str) -> Option<RegisteredTool> {
        self.mcp_manager
            .tool_by_name(name)
            .map(|tool| RegisteredTool {
                name: tool.name,
                description: tool.description,
                input_schema: tool.input_schema,
                extension_id: format!("mcp.{}", tool.server_name),
                approval_policy: tool.approval_policy,
                tenant_allowlist: Vec::new(),
                api_key_allowlist: Vec::new(),
                route_allowlist: Vec::new(),
            })
    }

    pub(crate) async fn execute_tool(
        &self,
        request: ToolExecutionRequest,
        request_id: String,
        tenant: ferrogate_core::TenantContext,
        api_key_id: Option<&str>,
    ) -> Result<ToolExecutionResponse, ToolExecutionError> {
        self.extension_registry
            .execute_tool(request, request_id, tenant, api_key_id)
            .await
    }

    pub(crate) async fn execute_mcp_tool(
        &self,
        request: ToolExecutionRequest,
        request_id: String,
        trace_id: Option<String>,
        tenant: ferrogate_core::TenantContext,
        identity_headers: McpDispatchHeaders,
    ) -> Result<ToolExecutionResponse, ToolExecutionError> {
        let (server_name, _) = request.name.split_once('-').ok_or_else(|| {
            ToolExecutionError::NotFound(format!(
                "MCP tool {} must use serverName-toolName namespace",
                request.name
            ))
        })?;
        let policy_request = RequestContext {
            request_id: request_id.clone(),
            trace_id,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            route: Some("/v1/mcp/tool/execute".into()),
            upstream: Some(format!("mcp:{server_name}")),
            tenant: tenant.clone(),
        };
        let policy_model = format!("mcp_tool:{}", request.name);
        let policy_provider = format!("mcp:{server_name}");
        if let PolicyDecision::Deny { code: _, message } =
            self.evaluate_policy(&policy_request, Some(&policy_model), Some(&policy_provider))
        {
            self.record_tool_billing_event(&request_id, &tenant, &request.name, 0, 403);
            return Err(ToolExecutionError::Denied(message));
        }

        let started = std::time::Instant::now();
        let mcp_manager = Arc::clone(&self.mcp_manager);
        let dispatch_timeout = self.mcp_dispatch_timeout();
        let cleanup_handle = mcp_manager.dispatch_cleanup_handle(&request.name);
        let dispatch_permit = Arc::clone(&self.mcp_dispatch_permits)
            .acquire_owned()
            .await
            .map_err(|_| {
                ToolExecutionError::Failed("MCP dispatch permit pool is unavailable".into())
            })?;
        let mcp_request = McpToolExecutionRequest {
            name: request.name.clone(),
            arguments: request.arguments.clone(),
        };
        let result = match tokio::time::timeout(
            dispatch_timeout,
            tokio::task::spawn_blocking(move || {
                let _permit = dispatch_permit;
                mcp_manager.execute_tool_with_headers(mcp_request, identity_headers)
            }),
        )
        .await
        {
            Ok(Ok(result)) => result.map_err(tool_error_from_mcp),
            Ok(Err(error)) => Err(ToolExecutionError::Failed(format!(
                "MCP dispatch task failed: {error}"
            ))),
            Err(_) => {
                if let Some(cleanup_handle) = cleanup_handle {
                    cleanup_handle.cleanup_after_timeout(dispatch_timeout);
                }
                Err(ToolExecutionError::Failed(format!(
                    "MCP tool {} timed out after {} seconds",
                    request.name,
                    dispatch_timeout.as_secs()
                )))
            }
        };
        let latency_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                self.record_tool_billing_event(
                    &request_id,
                    &tenant,
                    &request.name,
                    latency_ms,
                    502,
                );
                return Err(error);
            }
        };
        self.record_tool_billing_event(
            &request_id,
            &tenant,
            &request.name,
            latency_ms,
            if result.is_error { 502 } else { 200 },
        );
        Ok(tool_response_from_mcp(
            request, request_id, result, latency_ms,
        ))
    }

    pub(crate) fn run_pre_request_hooks(
        &self,
        request_id: &str,
        path: &str,
    ) -> Result<(), ToolExecutionError> {
        self.extension_registry.pre_request(request_id, path)
    }

    pub(crate) fn run_post_response_hooks(&self, request_id: &str, status: u16) {
        self.extension_registry.post_response(request_id, status);
    }
}
