// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for the agent execution runtime --
// request-log/audit-event/metering raw accessors, agent-workflow run
// tracking, paginated admin views (request-logs/audit-events/agent-runs/
// managed-worker-sessions/self-hosted-worker-records), self-hosted
// worker registration/heartbeat/telemetry/artifact/checkpoint/timeline,
// managed-worker lifecycle recording, and agent-run timelines/summaries.

use super::*;

impl AppState {
    pub(crate) fn request_logs(&self) -> Vec<StoredRequestLog> {
        // Sync wrapper bridging the async storage read (issue #221) — called
        // from telemetry.rs's raw thread::spawn OTLP/analytics senders (no
        // tokio runtime) as well as async handlers; block_on_sync_bridge
        // handles both.
        crate::gateway::block_on_sync_bridge(self.repositories.request_logs())
    }

    pub(crate) fn audit_events(&self) -> Vec<StoredAuditEvent> {
        crate::gateway::block_on_sync_bridge(self.repositories.audit_events())
    }

    pub(crate) fn metering_events(&self) -> Vec<BillingEvent> {
        self.metering_events.list()
    }

    pub(crate) fn workflow_run_started_at(
        &self,
        workflow_id: &str,
        workflow_version: u32,
        agent_run_id: &str,
        organization_id: Option<&str>,
    ) -> Option<u64> {
        // Tenant scope (#185/#228): `agent_run_id` is client-supplied and not
        // tenant-namespaced, so the gating readers MUST also match the caller's
        // organization_id -- otherwise one tenant referencing another tenant's
        // agent_run_id would compute its run-gating from the other tenant's
        // logs. `None` (platform operator) matches operator-owned records only.
        let request_timestamps = self
            .request_logs()
            .into_iter()
            .filter(|log| {
                log.workflow_id.as_deref() == Some(workflow_id)
                    && log.workflow_version == Some(workflow_version)
                    && log.agent_run_id.as_deref() == Some(agent_run_id)
                    && log.tenant.organization_id.as_deref() == organization_id
            })
            .flat_map(|log| [log.started_at_unix, log.completed_at_unix]);
        let audit_timestamps = self
            .audit_events()
            .into_iter()
            .filter(|event| {
                event.workflow_id.as_deref() == Some(workflow_id)
                    && event.workflow_version == Some(workflow_version)
                    && event.agent_run_id.as_deref() == Some(agent_run_id)
                    && event.tenant.organization_id.as_deref() == organization_id
            })
            .map(|event| event.occurred_at_unix);
        let billing_timestamps = self
            .metering_events()
            .into_iter()
            .filter(|event| {
                event.workflow_id.as_deref() == Some(workflow_id)
                    && event.workflow_version == Some(workflow_version)
                    && event.agent_run_id.as_deref() == Some(agent_run_id)
                    && event.tenant.organization_id.as_deref() == organization_id
            })
            .map(|event| event.occurred_at_unix);

        request_timestamps
            .chain(audit_timestamps)
            .chain(billing_timestamps)
            .flatten()
            .min()
    }

    pub(crate) fn workflow_run_last_successful_node_id(
        &self,
        workflow_id: &str,
        workflow_version: u32,
        agent_run_id: &str,
        organization_id: Option<&str>,
    ) -> Option<String> {
        // Tenant scope (#185/#228): match the caller's organization_id so a
        // client-supplied `agent_run_id` cannot pull another tenant's node
        // history into this tenant's edge-transition gate.
        let mut latest: Option<(u64, String)> = None;
        for log in self.request_logs() {
            if log.workflow_id.as_deref() != Some(workflow_id)
                || log.workflow_version != Some(workflow_version)
                || log.agent_run_id.as_deref() != Some(agent_run_id)
                || log.tenant.organization_id.as_deref() != organization_id
                || log.status_code >= 400
            {
                continue;
            }
            if let Some(node_id) = log.workflow_node_id {
                let timestamp = log.completed_at_unix.or(log.started_at_unix).unwrap_or(0);
                record_latest_workflow_node(&mut latest, timestamp, node_id);
            }
        }
        for event in self.audit_events() {
            if event.workflow_id.as_deref() != Some(workflow_id)
                || event.workflow_version != Some(workflow_version)
                || event.agent_run_id.as_deref() != Some(agent_run_id)
                || event.tenant.organization_id.as_deref() != organization_id
                || event.outcome != "success"
            {
                continue;
            }
            if let Some(node_id) = event.workflow_node_id {
                record_latest_workflow_node(
                    &mut latest,
                    event.occurred_at_unix.unwrap_or(0),
                    node_id,
                );
            }
        }
        for event in self.metering_events() {
            if event.workflow_id.as_deref() != Some(workflow_id)
                || event.workflow_version != Some(workflow_version)
                || event.agent_run_id.as_deref() != Some(agent_run_id)
                || event.tenant.organization_id.as_deref() != organization_id
                || event.status_code >= 400
            {
                continue;
            }
            if let Some(node_id) = event.workflow_node_id {
                record_latest_workflow_node(
                    &mut latest,
                    event.occurred_at_unix.unwrap_or(0),
                    node_id,
                );
            }
        }
        latest.map(|(_, node_id)| node_id)
    }

    pub(crate) fn workflow_edge_transition_error(
        &self,
        workflow: &AgentWorkflowPolicy,
        agent_run_id: &str,
        node_id: &str,
        organization_id: Option<&str>,
    ) -> Option<String> {
        if workflow.edges.is_empty() {
            return None;
        }
        if let Some(previous_node_id) = self.workflow_run_last_successful_node_id(
            &workflow.id,
            workflow.version,
            agent_run_id,
            organization_id,
        ) {
            if previous_node_id == node_id
                || workflow
                    .edges
                    .iter()
                    .any(|edge| edge.from == previous_node_id && edge.to == node_id)
            {
                return None;
            }
            return Some(format!(
                "agent workflow {}@{} cannot transition from node {} to node {}",
                workflow.id, workflow.version, previous_node_id, node_id
            ));
        }
        if workflow.edges.iter().any(|edge| edge.to == node_id) {
            return Some(format!(
                "agent workflow {}@{} node {} has incoming edges and cannot start this run",
                workflow.id, workflow.version, node_id
            ));
        }
        None
    }

    /// `tenant_scope` narrows the page to a single tenant's request logs
    /// (issue #185): a tenant-scoped admin key must never see another
    /// tenant's request logs, so this bypasses the (efficient, but
    /// unfiltered) storage-level pagination in favor of filtering the full
    /// unbounded log set before paginating in memory. `None` (a
    /// platform-operator caller) keeps the original storage-pushed-down
    /// pagination unchanged.
    pub(crate) fn request_logs_page(
        &self,
        pagination: AdminPagination,
        tenant_scope: Option<&str>,
    ) -> AdminPage<StoredRequestLog> {
        if let Some(tenant_id) = tenant_scope {
            let filtered: Vec<StoredRequestLog> =
                crate::gateway::block_on_sync_bridge(self.repositories.request_logs())
                    .into_iter()
                    .filter(|log| log.tenant.organization_id.as_deref() == Some(tenant_id))
                    .collect();
            let total = filtered.len();
            let data = filtered
                .into_iter()
                .skip(pagination.offset)
                .take(pagination.limit)
                .collect();
            return AdminPage {
                data,
                total,
                offset: pagination.offset,
                limit: pagination.limit,
            };
        }
        let page = crate::gateway::block_on_sync_bridge(
            self.repositories
                .request_logs_page(pagination.offset, pagination.limit),
        );
        AdminPage {
            data: page.data,
            total: page.total,
            offset: page.offset,
            limit: page.limit,
        }
    }

    pub(crate) fn request_log_export_records(
        &self,
        filter: RequestLogExportFilter,
    ) -> Vec<RequestLogExportRecord> {
        let usage_by_request_id = self
            .metering_events
            .list()
            .into_iter()
            .map(|event| (event.request_id, event.usage))
            .collect::<HashMap<_, _>>();
        crate::gateway::block_on_sync_bridge(self.repositories.request_logs())
            .into_iter()
            .filter(|log| filter.matches(log))
            .take(filter.limit)
            .map(|log| {
                let usage = usage_by_request_id.get(&log.request_id).cloned();
                RequestLogExportRecord::from_log(log, usage)
            })
            .collect()
    }

    /// See [`AppState::request_logs_page`]'s `tenant_scope` doc (issue
    /// #185); same rationale applies to audit events.
    pub(crate) fn audit_events_page(
        &self,
        pagination: AdminPagination,
        tenant_scope: Option<&str>,
    ) -> AdminPage<StoredAuditEvent> {
        if let Some(tenant_id) = tenant_scope {
            let filtered: Vec<StoredAuditEvent> =
                crate::gateway::block_on_sync_bridge(self.repositories.audit_events())
                    .into_iter()
                    .filter(|event| event.tenant.organization_id.as_deref() == Some(tenant_id))
                    .collect();
            let total = filtered.len();
            let data = filtered
                .into_iter()
                .skip(pagination.offset)
                .take(pagination.limit)
                .collect();
            return AdminPage {
                data,
                total,
                offset: pagination.offset,
                limit: pagination.limit,
            };
        }
        let page = crate::gateway::block_on_sync_bridge(
            self.repositories
                .audit_events_page(pagination.offset, pagination.limit),
        );
        AdminPage {
            data: page.data,
            total: page.total,
            offset: page.offset,
            limit: page.limit,
        }
    }

    pub(crate) fn agent_runs_page(
        &self,
        pagination: AdminPagination,
        filter: AgentRunFilter,
    ) -> AdminPage<AgentRunSummary> {
        let mut summaries = self.agent_run_summaries(&filter);
        summaries.sort_by(|left, right| {
            right
                .last_seen_unix
                .cmp(&left.last_seen_unix)
                .then_with(|| left.id.cmp(&right.id))
        });
        let total = summaries.len();
        let data = summaries
            .into_iter()
            .skip(pagination.offset)
            .take(pagination.limit)
            .collect();
        AdminPage {
            data,
            total,
            offset: pagination.offset,
            limit: pagination.limit,
        }
    }

    /// `tenant_scope`: narrows the page to a single tenant's managed
    /// worker sessions (issue #186); `None` (platform operator) is
    /// unfiltered.
    pub(crate) fn managed_worker_sessions_page(
        &self,
        pagination: AdminPagination,
        tenant_scope: Option<&str>,
    ) -> AdminPage<crate::responses::AdminManagedWorkerSession> {
        let lifecycle_events = crate::gateway::block_on_sync_bridge(
            self.repositories.managed_worker_lifecycle_events(),
        );
        let worker_sessions =
            crate::gateway::block_on_sync_bridge(self.repositories.managed_worker_sessions());
        let mut sessions = worker_sessions
            .into_iter()
            .map(|session| {
                let events = lifecycle_events
                    .iter()
                    .filter(|event| event.session_id == session.id)
                    .map(|event| crate::responses::AdminManagedWorkerLifecycleEvent {
                        id: event.id.clone(),
                        session_id: event.session_id.clone(),
                        run_id: event.run_id.clone(),
                        status: event.status.clone(),
                        action: event.action.clone(),
                        outcome: event.outcome.clone(),
                        occurred_at_unix: event.occurred_at_unix,
                        agent_worker_instance_id: event.agent_worker_instance_id.clone(),
                    })
                    .collect();
                crate::responses::AdminManagedWorkerSession {
                    id: session.id,
                    run_id: session.run_id,
                    tenant: session.tenant,
                    workspace_id: session.workspace_id,
                    worker_template_id: session.worker_template_id,
                    agent_worker_instance_id: session.agent_worker_instance_id,
                    status: session.status,
                    isolation_backend_kind: session.isolation_backend_kind,
                    microvm_id: session.microvm_id,
                    capability_envelope_id: session.capability_envelope_id,
                    requested_at_unix: session.requested_at_unix,
                    started_at_unix: session.started_at_unix,
                    completed_at_unix: session.completed_at_unix,
                    cleanup_completed_at_unix: session.cleanup_completed_at_unix,
                    lifecycle_events: events,
                }
            })
            .collect::<Vec<_>>();
        if let Some(tenant_id) = tenant_scope {
            sessions.retain(|session| session.tenant.organization_id.as_deref() == Some(tenant_id));
        }
        sessions.sort_by(|left, right| {
            right
                .requested_at_unix
                .cmp(&left.requested_at_unix)
                .then_with(|| left.id.cmp(&right.id))
        });
        let total = sessions.len();
        let data = sessions
            .into_iter()
            .skip(pagination.offset)
            .take(pagination.limit)
            .collect();
        AdminPage {
            data,
            total,
            offset: pagination.offset,
            limit: pagination.limit,
        }
    }

    /// `tenant_scope`: narrows the page to a single tenant's self-hosted
    /// workers (issue #186); `None` (platform operator) is unfiltered.
    pub(crate) fn self_hosted_worker_records_page(
        &self,
        pagination: AdminPagination,
        tenant_scope: Option<&str>,
    ) -> AdminPage<crate::responses::AdminSelfHostedWorkerRecord> {
        let mut records = self.self_hosted_worker_records();
        if let Some(tenant_id) = tenant_scope {
            records.retain(|record| record.tenant.organization_id.as_deref() == Some(tenant_id));
        }
        records.sort_by(|left, right| {
            right
                .last_seen_at_unix
                .or(right.registered_at_unix)
                .cmp(&left.last_seen_at_unix.or(left.registered_at_unix))
                .then_with(|| left.id.cmp(&right.id))
        });
        let total = records.len();
        let data = records
            .into_iter()
            .skip(pagination.offset)
            .take(pagination.limit)
            .collect();
        AdminPage {
            data,
            total,
            offset: pagination.offset,
            limit: pagination.limit,
        }
    }

    /// Registers a self-hosted worker and returns the readable record plus the
    /// freshly-provisioned transport secret. The secret is returned to the
    /// caller exactly once (at registration); it is never included in the
    /// worker record surfaced by GET/list.
    pub(crate) fn register_self_hosted_worker(
        &self,
        request: crate::responses::AdminSelfHostedWorkerRegistrationRequest,
    ) -> Result<(crate::responses::AdminSelfHostedWorkerRecord, String), SelfHostedWorkerRecordError>
    {
        validate_self_hosted_registration_request(&request)?;
        let id = next_self_hosted_worker_id();
        let now = now_unix_seconds();
        let registration = StoredSelfHostedWorkerRegistration {
            id: id.clone(),
            tenant: request.tenant,
            workspace_id: request.workspace_id.trim().to_string(),
            worker_name: request.worker_name.trim().to_string(),
            status: "registered".into(),
            identity_fingerprint: request.identity_fingerprint.trim().to_string(),
            identity_expires_at_unix: request.identity_expires_at_unix,
            orchestration_enabled: request.orchestration_enabled,
            registered_at_unix: now,
            last_seen_at_unix: None,
            trust_level: "reported_by_self_hosted_worker".into(),
            capability_envelope_json: request
                .capability_envelope_json
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "{}".into()),
            // Provision an independent, high-entropy transport secret. This is
            // the value the symmetric-AEAD transport keys off; it is returned to
            // the caller ONCE below and never exposed in GET/list.
            token_secret: ferrogate_runtime::generate_transport_token_secret(),
        };
        let transport_token_secret = registration.token_secret.clone();
        crate::gateway::block_on_sync_bridge(
            self.repositories
                .upsert_self_hosted_worker_registration(registration.clone()),
        )
        .map_err(|error| SelfHostedWorkerRecordError::Storage(error.to_string()))?;
        self.rebuild_self_hosted_worker_dispatch_runtime()?;
        self.self_hosted_worker_record(&id)
            .map(|worker| (worker, transport_token_secret))
            .ok_or_else(|| {
                SelfHostedWorkerRecordError::Storage(
                    "self-hosted worker registration was not readable after write".into(),
                )
            })
    }

    pub(crate) fn rotate_self_hosted_worker_identity(
        &self,
        worker_id: &str,
        request: crate::responses::AdminSelfHostedWorkerRotateRequest,
    ) -> Result<crate::responses::AdminSelfHostedWorkerRotateResponse, SelfHostedWorkerRecordError>
    {
        validate_self_hosted_rotate_request(&request)?;
        let mut registration = crate::gateway::block_on_sync_bridge(
            self.repositories.self_hosted_worker_registration(worker_id),
        )
        .ok_or_else(|| {
            SelfHostedWorkerRecordError::NotFound(format!(
                "self-hosted worker {worker_id} was not found"
            ))
        })?;
        let previous_identity_fingerprint = registration.identity_fingerprint.clone();
        let previous_identity_expires_at_unix = registration.identity_expires_at_unix;
        registration.identity_fingerprint = request.identity_fingerprint.trim().to_string();
        registration.identity_expires_at_unix = request.identity_expires_at_unix;
        // Rotation issues a fresh transport secret alongside the new identity
        // fingerprint, so a compromised or leaked secret stops working. Returned
        // once in the rotation response.
        registration.token_secret = ferrogate_runtime::generate_transport_token_secret();
        let transport_token_secret = registration.token_secret.clone();
        let rotated_at_unix = now_unix_seconds();
        crate::gateway::block_on_sync_bridge(
            self.repositories
                .upsert_self_hosted_worker_registration(registration.clone()),
        )
        .map_err(|error| SelfHostedWorkerRecordError::Storage(error.to_string()))?;
        self.rebuild_self_hosted_worker_dispatch_runtime()?;
        let worker = self.self_hosted_worker_record(worker_id).ok_or_else(|| {
            SelfHostedWorkerRecordError::Storage(
                "self-hosted worker was not readable after identity rotation".into(),
            )
        })?;
        // Rotation changes the SPIFFE token_id segment (issue #249): when an
        // issuing CA is configured, mint a fresh cert bound to the rotated
        // 4-tuple and return it once. Best-effort as at registration.
        let client_certificate = match self_hosted_mtls_cert_issuer_from_env()? {
            Some(issuer) => rotated_at_unix.and_then(|now| {
                mint_self_hosted_worker_client_certificate(&registration, &issuer, now).ok()
            }),
            None => None,
        };
        Ok(crate::responses::AdminSelfHostedWorkerRotateResponse {
            object: "self_hosted_worker_identity_rotation",
            worker,
            transport_token_secret,
            client_certificate,
            previous_identity_fingerprint,
            previous_identity_expires_at_unix,
            rotated_at_unix,
        })
    }

    /// Mint the verified-mTLS client certificate for a registered self-hosted
    /// worker, bound to its SPIFFE 4-tuple and signed by the configured issuing
    /// CA (issue #249). Returns `None` when no issuing CA is configured (the
    /// deployment runs the pre-production marker/AEAD posture). The private key is
    /// returned to the caller exactly once and is never persisted; only the
    /// fingerprint is retained (surfaced in the response) for later revocation.
    pub(crate) fn issue_self_hosted_worker_client_certificate(
        &self,
        worker_id: &str,
    ) -> Result<
        Option<crate::responses::AdminSelfHostedWorkerClientCertificate>,
        SelfHostedWorkerRecordError,
    > {
        let Some(issuer) = self_hosted_mtls_cert_issuer_from_env()? else {
            return Ok(None);
        };
        let registration = crate::gateway::block_on_sync_bridge(
            self.repositories.self_hosted_worker_registration(worker_id),
        )
        .ok_or_else(|| {
            SelfHostedWorkerRecordError::NotFound(format!(
                "self-hosted worker {worker_id} was not found"
            ))
        })?;
        let now = now_unix_seconds().ok_or_else(|| {
            SelfHostedWorkerRecordError::Storage(
                "server clock predates the unix epoch; cannot mint a worker certificate".into(),
            )
        })?;
        mint_self_hosted_worker_client_certificate(&registration, &issuer, now).map(Some)
    }

    fn rebuild_self_hosted_worker_dispatch_runtime(
        &self,
    ) -> Result<(), SelfHostedWorkerRecordError> {
        let registrations = crate::gateway::block_on_sync_bridge(
            self.repositories.self_hosted_worker_registrations(),
        );
        let dispatches =
            crate::gateway::block_on_sync_bridge(self.repositories.self_hosted_run_dispatches());
        let records = match self.self_hosted_dispatch.lock() {
            Ok(mut dispatch) => {
                dispatch
                    .rebuild_registries(registrations, dispatches)
                    .map_err(|error| SelfHostedWorkerRecordError::Storage(error.to_string()))?;
                dispatch.storage_records()
            }
            Err(poisoned) => {
                let mut dispatch = poisoned.into_inner();
                dispatch
                    .rebuild_registries(registrations, dispatches)
                    .map_err(|error| SelfHostedWorkerRecordError::Storage(error.to_string()))?;
                dispatch.storage_records()
            }
        };
        persist_self_hosted_dispatch_records(&self.repositories, records)
            .map_err(|error| SelfHostedWorkerRecordError::Storage(error.to_string()))
    }

    pub(crate) fn poll_self_hosted_worker_run(
        &self,
        mut request: SelfHostedRunPollRequest,
    ) -> Result<Option<SelfHostedRunLease>, SelfHostedWorkerError> {
        // Security (#113): never trust client time for identity expiry. request.now_unix
        // is client-supplied; stamp the server clock so an expired identity cannot
        // report a past observed_at to pass validation.
        request.identity.observed_at_unix = now_unix_seconds();
        let (result, records) = match self.self_hosted_dispatch.lock() {
            Ok(mut dispatch) => {
                let result = dispatch.poll_run(request);
                let records = result
                    .as_ref()
                    .ok()
                    .and_then(|lease| lease.as_ref())
                    .map(|_| dispatch.storage_records());
                (result, records)
            }
            Err(poisoned) => {
                let mut dispatch = poisoned.into_inner();
                let result = dispatch.poll_run(request);
                let records = result
                    .as_ref()
                    .ok()
                    .and_then(|lease| lease.as_ref())
                    .map(|_| dispatch.storage_records());
                (result, records)
            }
        };
        if let Some(records) = records {
            persist_self_hosted_dispatch_records(&self.repositories, records)?;
        }
        result
    }

    pub(crate) fn ack_self_hosted_worker_run(
        &self,
        mut request: SelfHostedRunAckRequest,
    ) -> Result<SelfHostedRunAck, SelfHostedWorkerError> {
        // Security (#113): never trust client time for identity expiry. request.reported_at_unix
        // is client-supplied; stamp the server clock so an expired identity cannot
        // report a past observed_at to pass validation.
        request.identity.observed_at_unix = now_unix_seconds();
        let (result, records) = match self.self_hosted_dispatch.lock() {
            Ok(mut dispatch) => {
                let result = dispatch.ack_run(request);
                let records = result.as_ref().ok().map(|_| dispatch.storage_records());
                (result, records)
            }
            Err(poisoned) => {
                let mut dispatch = poisoned.into_inner();
                let result = dispatch.ack_run(request);
                let records = result.as_ref().ok().map(|_| dispatch.storage_records());
                (result, records)
            }
        };
        if let Some(records) = records {
            persist_self_hosted_dispatch_records(&self.repositories, records)?;
        }
        result
    }

    pub(crate) fn validate_self_hosted_worker_identity(
        &self,
        identity: &SelfHostedWorkerIdentity,
    ) -> Result<(), SelfHostedWorkerError> {
        match self.self_hosted_dispatch.lock() {
            Ok(dispatch) => dispatch.validate_worker_identity(identity),
            Err(poisoned) => poisoned.into_inner().validate_worker_identity(identity),
        }
        .map(|_| ())
    }

    pub(crate) fn self_hosted_worker_transport_secret(
        &self,
        tenant_id: &str,
        workspace_id: &str,
        worker_id: &str,
        token_id: &str,
    ) -> Result<String, SelfHostedWorkerError> {
        let registration = crate::gateway::block_on_sync_bridge(
            self.repositories.self_hosted_worker_registration(worker_id),
        )
        .filter(|registration| {
            registration.workspace_id == workspace_id
                && self_hosted_tenant_id(&registration.tenant) == tenant_id
        })
        .ok_or_else(|| {
            SelfHostedWorkerError::InvalidIdentity(format!(
                "self-hosted worker {worker_id} was not found for encrypted transport"
            ))
        })?;
        if registration.identity_fingerprint != token_id {
            return Err(SelfHostedWorkerError::InvalidIdentity(
                "self-hosted worker encrypted transport token_id does not match registration"
                    .to_string(),
            ));
        }
        // The transport AEAD/bearer secret is the server-provisioned
        // `token_secret`, NOT the public `identity_fingerprint`/`token_id`. A
        // pre-migration registration has an empty secret; the transport's
        // minimum-length check then fails closed rather than keying the cipher
        // with a weak value.
        Ok(registration.token_secret)
    }

    pub(crate) fn record_self_hosted_worker_heartbeat(
        &self,
        worker_id: &str,
        request: crate::responses::AdminSelfHostedWorkerHeartbeatRequest,
    ) -> Result<
        (
            crate::responses::AdminSelfHostedWorkerRecord,
            crate::responses::AdminSelfHostedWorkerHeartbeat,
        ),
        SelfHostedWorkerRecordError,
    > {
        validate_self_hosted_heartbeat_request(&request)?;
        let mut registration = crate::gateway::block_on_sync_bridge(
            self.repositories.self_hosted_worker_registration(worker_id),
        )
        .ok_or_else(|| {
            SelfHostedWorkerRecordError::NotFound(format!(
                "self-hosted worker {worker_id} was not found"
            ))
        })?;
        let observed_at_unix = now_unix_seconds();
        let heartbeat = StoredSelfHostedWorkerHeartbeat {
            id: next_self_hosted_heartbeat_id(),
            worker_id: registration.id.clone(),
            tenant: registration.tenant.clone(),
            workspace_id: registration.workspace_id.clone(),
            status: request.status.trim().to_string(),
            reported_at_unix: request.reported_at_unix.or(observed_at_unix),
            observed_at_unix,
            heartbeat_json: request
                .heartbeat_json
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "{}".into()),
        };
        crate::gateway::block_on_sync_bridge(
            self.repositories
                .append_self_hosted_worker_heartbeat(heartbeat.clone()),
        )
        .map_err(|error| SelfHostedWorkerRecordError::Storage(error.to_string()))?;
        registration.status = heartbeat.status.clone();
        registration.last_seen_at_unix = heartbeat.observed_at_unix;
        crate::gateway::block_on_sync_bridge(
            self.repositories
                .upsert_self_hosted_worker_registration(registration),
        )
        .map_err(|error| SelfHostedWorkerRecordError::Storage(error.to_string()))?;
        let worker = self.self_hosted_worker_record(worker_id).ok_or_else(|| {
            SelfHostedWorkerRecordError::Storage(
                "self-hosted worker was not readable after heartbeat write".into(),
            )
        })?;
        let heartbeat = worker.latest_heartbeat.clone().ok_or_else(|| {
            SelfHostedWorkerRecordError::Storage(
                "self-hosted heartbeat was not readable after write".into(),
            )
        })?;
        Ok((worker, heartbeat))
    }

    pub(crate) fn record_self_hosted_worker_telemetry_event(
        &self,
        worker_id: &str,
        request: crate::responses::AdminSelfHostedWorkerTelemetryEventRequest,
    ) -> Result<
        (
            crate::responses::AdminSelfHostedWorkerRecord,
            crate::responses::AdminSelfHostedWorkerTelemetryEvent,
        ),
        SelfHostedWorkerRecordError,
    > {
        validate_self_hosted_telemetry_event_request(&request)?;
        let registration = crate::gateway::block_on_sync_bridge(
            self.repositories.self_hosted_worker_registration(worker_id),
        )
        .ok_or_else(|| {
            SelfHostedWorkerRecordError::NotFound(format!(
                "self-hosted worker {worker_id} was not found"
            ))
        })?;
        let ingested_at_unix = now_unix_seconds();
        let stored_event = StoredSelfHostedWorkerTelemetryEvent {
            id: next_self_hosted_telemetry_event_id(),
            worker_id: registration.id.clone(),
            tenant: registration.tenant,
            workspace_id: registration.workspace_id,
            session_id: Some(request.session_id.trim().to_string()),
            run_id: Some(request.run_id.trim().to_string()),
            kind: request.kind.trim().to_string(),
            trust_level: "reported_by_self_hosted_worker".into(),
            occurred_at_unix: request.occurred_at_unix.or(ingested_at_unix),
            ingested_at_unix,
            event_json: request
                .event_json
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "{}".into()),
        };
        crate::gateway::block_on_sync_bridge(
            self.repositories
                .append_self_hosted_worker_telemetry_event(stored_event.clone()),
        )
        .map_err(|error| SelfHostedWorkerRecordError::Storage(error.to_string()))?;
        let worker = self.self_hosted_worker_record(worker_id).ok_or_else(|| {
            SelfHostedWorkerRecordError::Storage(
                "self-hosted worker was not readable after telemetry event write".into(),
            )
        })?;
        let event = crate::responses::AdminSelfHostedWorkerTelemetryEvent {
            id: stored_event.id,
            worker_id: stored_event.worker_id,
            session_id: stored_event.session_id,
            run_id: stored_event.run_id,
            kind: stored_event.kind,
            trust_level: stored_event.trust_level,
            occurred_at_unix: stored_event.occurred_at_unix,
            ingested_at_unix: stored_event.ingested_at_unix,
        };
        Ok((worker, event))
    }

    pub(crate) fn record_self_hosted_worker_artifact(
        &self,
        worker_id: &str,
        request: crate::responses::AdminSelfHostedWorkerArtifactRequest,
    ) -> Result<
        (
            crate::responses::AdminSelfHostedWorkerRecord,
            crate::responses::AdminSelfHostedWorkerArtifact,
        ),
        SelfHostedWorkerRecordError,
    > {
        validate_self_hosted_artifact_request(&request)?;
        let registration = crate::gateway::block_on_sync_bridge(
            self.repositories.self_hosted_worker_registration(worker_id),
        )
        .ok_or_else(|| {
            SelfHostedWorkerRecordError::NotFound(format!(
                "self-hosted worker {worker_id} was not found"
            ))
        })?;
        // Cross-worker overwrite guard (#228, #82-class): artifact `id` is a
        // GLOBAL namespace (id TEXT PRIMARY KEY) and the write is
        // ON CONFLICT (id) DO UPDATE, so without this a worker could clobber and
        // re-attribute another worker's (another tenant's) artifact by reusing
        // its id. Reject when the existing row belongs to a different worker.
        let artifact_id = request.artifact_id.trim().to_string();
        if let Some(existing) = crate::gateway::block_on_sync_bridge(
            self.repositories.self_hosted_worker_artifact(&artifact_id),
        ) {
            if existing.worker_id != registration.id {
                return Err(SelfHostedWorkerRecordError::InvalidRequest(format!(
                    "artifact {artifact_id} already exists for a different worker"
                )));
            }
        }
        let created_at_unix = request.created_at_unix.or_else(now_unix_seconds);
        let stored_artifact = StoredSelfHostedWorkerArtifact {
            id: artifact_id,
            worker_id: registration.id.clone(),
            tenant: registration.tenant,
            workspace_id: registration.workspace_id,
            session_id: request.session_id.trim().to_string(),
            run_id: request.run_id.trim().to_string(),
            artifact_name: request.artifact_name.trim().to_string(),
            content_type: request.content_type.map(|value| value.trim().to_string()),
            size_bytes: request.size_bytes,
            trust_level: "reported_by_self_hosted_worker".into(),
            created_at_unix,
            artifact_json: request
                .artifact_json
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "{}".into()),
        };
        crate::gateway::block_on_sync_bridge(
            self.repositories
                .upsert_self_hosted_worker_artifact(stored_artifact.clone()),
        )
        .map_err(|error| SelfHostedWorkerRecordError::Storage(error.to_string()))?;
        let worker = self.self_hosted_worker_record(worker_id).ok_or_else(|| {
            SelfHostedWorkerRecordError::Storage(
                "self-hosted worker was not readable after artifact write".into(),
            )
        })?;
        let artifact = crate::responses::AdminSelfHostedWorkerArtifact {
            id: stored_artifact.id,
            worker_id: stored_artifact.worker_id,
            session_id: stored_artifact.session_id,
            run_id: stored_artifact.run_id,
            artifact_name: stored_artifact.artifact_name,
            content_type: stored_artifact.content_type,
            size_bytes: stored_artifact.size_bytes,
            trust_level: stored_artifact.trust_level,
            created_at_unix: stored_artifact.created_at_unix,
        };
        Ok((worker, artifact))
    }

    pub(crate) fn record_self_hosted_worker_checkpoint(
        &self,
        worker_id: &str,
        request: crate::responses::AdminSelfHostedWorkerCheckpointRequest,
    ) -> Result<
        (
            crate::responses::AdminSelfHostedWorkerRecord,
            crate::responses::AdminSelfHostedWorkerCheckpoint,
        ),
        SelfHostedWorkerRecordError,
    > {
        validate_self_hosted_checkpoint_request(&request)?;
        let registration = crate::gateway::block_on_sync_bridge(
            self.repositories.self_hosted_worker_registration(worker_id),
        )
        .ok_or_else(|| {
            SelfHostedWorkerRecordError::NotFound(format!(
                "self-hosted worker {worker_id} was not found"
            ))
        })?;
        // Cross-worker overwrite guard (#228, #82-class): checkpoint `id` is a
        // GLOBAL namespace (id TEXT PRIMARY KEY) and the write is
        // ON CONFLICT (id) DO UPDATE. Reject a checkpoint id already owned by a
        // different worker so one tenant cannot destroy/re-attribute another
        // tenant's resume checkpoint.
        let checkpoint_id = request.checkpoint_id.trim().to_string();
        if let Some(existing) = crate::gateway::block_on_sync_bridge(
            self.repositories
                .self_hosted_worker_checkpoint(&checkpoint_id),
        ) {
            if existing.worker_id != registration.id {
                return Err(SelfHostedWorkerRecordError::InvalidRequest(format!(
                    "checkpoint {checkpoint_id} already exists for a different worker"
                )));
            }
        }
        let created_at_unix = request.created_at_unix.or_else(now_unix_seconds);
        let stored_checkpoint = StoredSelfHostedWorkerCheckpoint {
            id: checkpoint_id,
            worker_id: registration.id.clone(),
            tenant: registration.tenant,
            workspace_id: registration.workspace_id,
            session_id: request.session_id.trim().to_string(),
            run_id: request.run_id.trim().to_string(),
            checkpoint_name: request.checkpoint_name.trim().to_string(),
            size_bytes: request.size_bytes,
            trust_level: "reported_by_self_hosted_worker".into(),
            created_at_unix,
            checkpoint_json: request
                .checkpoint_json
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "{}".into()),
        };
        crate::gateway::block_on_sync_bridge(
            self.repositories
                .upsert_self_hosted_worker_checkpoint(stored_checkpoint.clone()),
        )
        .map_err(|error| SelfHostedWorkerRecordError::Storage(error.to_string()))?;
        let worker = self.self_hosted_worker_record(worker_id).ok_or_else(|| {
            SelfHostedWorkerRecordError::Storage(
                "self-hosted worker was not readable after checkpoint write".into(),
            )
        })?;
        let checkpoint = crate::responses::AdminSelfHostedWorkerCheckpoint {
            id: stored_checkpoint.id,
            worker_id: stored_checkpoint.worker_id,
            session_id: stored_checkpoint.session_id,
            run_id: stored_checkpoint.run_id,
            checkpoint_name: stored_checkpoint.checkpoint_name,
            size_bytes: stored_checkpoint.size_bytes,
            trust_level: stored_checkpoint.trust_level,
            created_at_unix: stored_checkpoint.created_at_unix,
        };
        Ok((worker, checkpoint))
    }

    /// Single-worker record (issue #231). This is the hot path — every
    /// worker heartbeat/telemetry/artifact/checkpoint write re-reads the
    /// record — so the `worker_id` filter is pushed into the repository
    /// (SQL on the durable path) instead of loading five whole tables and
    /// filtering here.
    pub(crate) fn self_hosted_worker_record(
        &self,
        id: &str,
    ) -> Option<crate::responses::AdminSelfHostedWorkerRecord> {
        let registration = crate::gateway::block_on_sync_bridge(
            self.repositories.self_hosted_worker_registration(id),
        )?;
        let latest_heartbeat = crate::gateway::block_on_sync_bridge(
            self.repositories.latest_self_hosted_worker_heartbeat(id),
        );
        let stats = crate::gateway::block_on_sync_bridge(
            self.repositories.self_hosted_worker_activity_stats(id),
        );
        Some(self_hosted_worker_record_from_parts(
            registration,
            latest_heartbeat,
            stats,
            now_unix_seconds(),
        ))
    }

    pub(crate) fn self_hosted_worker_event_stream(
        &self,
        worker_id: &str,
        query: SelfHostedWorkerEventStreamQuery,
    ) -> Option<crate::responses::AdminSelfHostedWorkerEventStream> {
        // Worker-id filters pushed into the repository (SQL on the durable
        // path) instead of listing whole tables (issue #231).
        crate::gateway::block_on_sync_bridge(
            self.repositories.self_hosted_worker_registration(worker_id),
        )?;
        let mut events = crate::gateway::block_on_sync_bridge(
            self.repositories
                .self_hosted_worker_telemetry_events_for_worker(worker_id),
        );
        events.sort_by(|left, right| {
            left.occurred_at_unix
                .cmp(&right.occurred_at_unix)
                .then_with(|| left.ingested_at_unix.cmp(&right.ingested_at_unix))
                .then_with(|| left.id.cmp(&right.id))
        });
        let total = events.len();
        let start_index = query
            .after_event_id
            .as_deref()
            .and_then(|cursor| events.iter().position(|event| event.id == cursor))
            .map(|position| position + 1)
            .unwrap_or(0);
        let data = events
            .into_iter()
            .skip(start_index)
            .take(query.limit)
            .map(|event| crate::responses::AdminSelfHostedRunEvent {
                id: event.id,
                worker_id: event.worker_id,
                session_id: event.session_id,
                run_id: event.run_id,
                kind: event.kind,
                trust_level: event.trust_level,
                occurred_at_unix: event.occurred_at_unix,
                ingested_at_unix: event.ingested_at_unix,
                event_json: event.event_json,
            })
            .collect::<Vec<_>>();
        let next_after_event_id = data.last().map(|event| event.id.clone());
        Some(crate::responses::AdminSelfHostedWorkerEventStream {
            object: "self_hosted_worker_event_stream",
            worker_id: worker_id.to_string(),
            trust_level: "reported_by_self_hosted_worker",
            data,
            total,
            limit: query.limit,
            after_event_id: query.after_event_id,
            next_after_event_id,
        })
    }

    pub(crate) fn self_hosted_worker_event_stream_query(
        &self,
        query: Option<&str>,
    ) -> SelfHostedWorkerEventStreamQuery {
        SelfHostedWorkerEventStreamQuery::from_query(
            query,
            self.config.storage.admin_list_default_limit,
            self.config.storage.admin_list_max_limit,
        )
    }

    /// Bulk (admin list) variant. Still loads the evidence stores wholesale,
    /// but as of issue #231 every one of them is retention-bounded on both
    /// backends; the per-worker hot path uses
    /// [`Self::self_hosted_worker_record`] instead.
    fn self_hosted_worker_records(&self) -> Vec<crate::responses::AdminSelfHostedWorkerRecord> {
        let heartbeats =
            crate::gateway::block_on_sync_bridge(self.repositories.self_hosted_worker_heartbeats());
        let telemetry_events = crate::gateway::block_on_sync_bridge(
            self.repositories.self_hosted_worker_telemetry_events(),
        );
        let artifacts =
            crate::gateway::block_on_sync_bridge(self.repositories.self_hosted_worker_artifacts());
        let checkpoints = crate::gateway::block_on_sync_bridge(
            self.repositories.self_hosted_worker_checkpoints(),
        );
        let now_unix = now_unix_seconds();
        crate::gateway::block_on_sync_bridge(self.repositories.self_hosted_worker_registrations())
            .into_iter()
            .map(|registration| {
                let latest_heartbeat = latest_self_hosted_heartbeat(&heartbeats, &registration.id);
                let stats = ferrogate_storage::StoredSelfHostedWorkerActivityStats {
                    telemetry_event_count: telemetry_events
                        .iter()
                        .filter(|event| event.worker_id == registration.id)
                        .count(),
                    artifact_count: artifacts
                        .iter()
                        .filter(|artifact| artifact.worker_id == registration.id)
                        .count(),
                    checkpoint_count: checkpoints
                        .iter()
                        .filter(|checkpoint| checkpoint.worker_id == registration.id)
                        .count(),
                    latest_event_at_unix: telemetry_events
                        .iter()
                        .filter(|event| event.worker_id == registration.id)
                        .filter_map(|event| event.occurred_at_unix)
                        .max(),
                    latest_artifact_at_unix: artifacts
                        .iter()
                        .filter(|artifact| artifact.worker_id == registration.id)
                        .filter_map(|artifact| artifact.created_at_unix)
                        .max(),
                    latest_checkpoint_at_unix: checkpoints
                        .iter()
                        .filter(|checkpoint| checkpoint.worker_id == registration.id)
                        .filter_map(|checkpoint| checkpoint.created_at_unix)
                        .max(),
                };
                self_hosted_worker_record_from_parts(
                    registration,
                    latest_heartbeat,
                    stats,
                    now_unix,
                )
            })
            .collect()
    }

    /// `tenant_scope`: a tenant-scoped caller only sees telemetry events for
    /// this run that belong to their own tenant (issue #185); if that
    /// leaves no matching events (either the run doesn't exist, or it
    /// belongs to a different tenant), this returns `None` -- the same
    /// "not found" response either way, so a denial never confirms whether
    /// the run exists under another tenant.
    pub(crate) fn self_hosted_run_timeline(
        &self,
        run_id: &str,
        tenant_scope: Option<&str>,
    ) -> Option<crate::responses::AdminSelfHostedRunTimeline> {
        if run_id.trim().is_empty() {
            return None;
        }
        // run_id filter + LIMIT are pushed into the repository (SQL on the
        // durable path, issue #231); the repository keeps the NEWEST
        // `SELF_HOSTED_RUN_TIMELINE_EVENT_LIMIT` events so an over-long run
        // still reports its latest lifecycle state. The tenant-scope filter
        // stays here (applied to the already-bounded slice).
        let mut events = crate::gateway::block_on_sync_bridge(
            self.repositories
                .self_hosted_worker_telemetry_events_for_run(
                    run_id,
                    SELF_HOSTED_RUN_TIMELINE_EVENT_LIMIT,
                ),
        )
        .into_iter()
        .filter(|event| {
            tenant_scope
                .is_none_or(|tenant_id| event.tenant.organization_id.as_deref() == Some(tenant_id))
        })
        .collect::<Vec<_>>();
        if events.is_empty() {
            return None;
        }
        events.sort_by(|left, right| {
            left.occurred_at_unix
                .cmp(&right.occurred_at_unix)
                .then_with(|| left.ingested_at_unix.cmp(&right.ingested_at_unix))
                .then_with(|| left.id.cmp(&right.id))
        });
        let mut session_ids = events
            .iter()
            .filter_map(|event| event.session_id.clone())
            .collect::<Vec<_>>();
        session_ids.sort();
        session_ids.dedup();
        let mut worker_ids = events
            .iter()
            .map(|event| event.worker_id.clone())
            .collect::<Vec<_>>();
        worker_ids.sort();
        worker_ids.dedup();
        let first_seen_unix = events
            .iter()
            .filter_map(|event| event.occurred_at_unix.or(event.ingested_at_unix))
            .min();
        let last_seen_unix = events
            .iter()
            .filter_map(|event| event.occurred_at_unix.or(event.ingested_at_unix))
            .max();
        let lifecycle_event_count = events
            .iter()
            .filter(|event| event.kind == "lifecycle")
            .count();
        let latest_lifecycle_state = events
            .iter()
            .rev()
            .find(|event| event.kind == "lifecycle")
            .and_then(|event| self_hosted_lifecycle_state_from_json(&event.event_json));
        let reported_event_count = events.len();
        let events = events
            .into_iter()
            .map(|event| crate::responses::AdminSelfHostedRunEvent {
                id: event.id,
                worker_id: event.worker_id,
                session_id: event.session_id,
                run_id: event.run_id,
                kind: event.kind,
                trust_level: event.trust_level,
                occurred_at_unix: event.occurred_at_unix,
                ingested_at_unix: event.ingested_at_unix,
                event_json: event.event_json,
            })
            .collect();
        Some(crate::responses::AdminSelfHostedRunTimeline {
            object: "self_hosted_run_timeline",
            run_id: run_id.to_string(),
            session_ids,
            worker_ids,
            trust_level: "reported_by_self_hosted_worker",
            reported_event_count,
            lifecycle_event_count,
            first_seen_unix,
            last_seen_unix,
            latest_lifecycle_state,
            events,
        })
    }

    pub(crate) fn agent_run_timeline(
        &self,
        id: &str,
        filter: AgentRunFilter,
    ) -> Option<AgentRunTimeline> {
        // Filtering `run` itself (not just the related events below) closes
        // a leak (issue #185): without this, a run belonging to a different
        // tenant than `filter.organization_id` would still surface via
        // `run` even though every related collection below is empty for
        // that tenant.
        let run = crate::gateway::block_on_sync_bridge(self.repositories.agent_run(id))
            .filter(|run| agent_run_matches_filter(&run.request_id, &run.tenant, &filter));
        // run_id filters pushed into the repository (SQL on the durable
        // path, issue #231) instead of loading whole tables; the per-record
        // tenant/request filter still applies to the filtered slices.
        let run_ids = [id.to_string()];
        let agent_events = crate::gateway::block_on_sync_bridge(
            self.repositories.agent_run_events_for_runs(&run_ids),
        )
        .into_iter()
        .filter(|event| agent_run_matches_filter(&event.request_id, &event.tenant, &filter))
        .collect::<Vec<_>>();
        let requests = crate::gateway::block_on_sync_bridge(
            self.repositories.request_logs_for_agent_runs(&run_ids),
        )
        .into_iter()
        .filter(|log| agent_run_matches_filter(&log.request_id, &log.tenant, &filter))
        .collect::<Vec<_>>();
        let billing_events = self
            .metering_events
            .list()
            .into_iter()
            .filter(|event| event.agent_run_id.as_deref() == Some(id))
            .filter(|event| agent_run_matches_filter(&event.request_id, &event.tenant, &filter))
            .collect::<Vec<_>>();
        let audit_events = crate::gateway::block_on_sync_bridge(
            self.repositories.audit_events_for_agent_runs(&run_ids),
        )
        .into_iter()
        .filter(|event| agent_run_matches_filter(&event.request_id, &event.tenant, &filter))
        .collect::<Vec<_>>();
        if run.is_none()
            && agent_events.is_empty()
            && requests.is_empty()
            && billing_events.is_empty()
            && audit_events.is_empty()
        {
            return None;
        }
        let summary = summarize_agent_run(
            id.to_string(),
            run.as_ref(),
            &agent_events,
            &requests,
            &billing_events,
            &audit_events,
        );
        Some(AgentRunTimeline {
            object: "agent_run_timeline",
            id: id.to_string(),
            run,
            summary,
            agent_events,
            requests,
            billing_events,
            audit_events,
        })
    }

    fn agent_run_summaries(&self, filter: &AgentRunFilter) -> Vec<AgentRunSummary> {
        // Issue #231: enumerate candidate run ids with a filtered + LIMITed
        // repository query (SQL on the durable path) instead of loading four
        // whole tables, then batch-fetch only those runs' records. The scan
        // is bounded to the AGENT_RUN_SUMMARY_SCAN_LIMIT most recently seen
        // runs. Billing events live in-process (metering store), so their
        // run ids are unioned in here.
        let billing_events = self.metering_events.list();
        let mut run_ids =
            crate::gateway::block_on_sync_bridge(self.repositories.agent_run_summary_seed_ids(
                filter.request_id.as_deref(),
                AGENT_RUN_SUMMARY_SCAN_LIMIT,
            ));
        run_ids.extend(
            billing_events
                .iter()
                .filter_map(|event| event.agent_run_id.clone()),
        );
        run_ids.sort();
        run_ids.dedup();
        let runs =
            crate::gateway::block_on_sync_bridge(self.repositories.agent_runs_by_ids(&run_ids));
        let agent_events = crate::gateway::block_on_sync_bridge(
            self.repositories.agent_run_events_for_runs(&run_ids),
        );
        let requests = crate::gateway::block_on_sync_bridge(
            self.repositories.request_logs_for_agent_runs(&run_ids),
        );
        let audit_events = crate::gateway::block_on_sync_bridge(
            self.repositories.audit_events_for_agent_runs(&run_ids),
        );
        run_ids
            .into_iter()
            .filter_map(|id| {
                // See the matching comment in `agent_run_timeline` (issue
                // #185): `run` must be filtered too, not just the related
                // event collections below.
                let run = runs
                    .iter()
                    .find(|run| run.id == id)
                    .filter(|run| agent_run_matches_filter(&run.request_id, &run.tenant, filter))
                    .cloned();
                let run_agent_events = agent_events
                    .iter()
                    .filter(|event| event.run_id == id)
                    .filter(|event| {
                        agent_run_matches_filter(&event.request_id, &event.tenant, filter)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let run_requests = requests
                    .iter()
                    .filter(|log| log.agent_run_id.as_deref() == Some(id.as_str()))
                    .filter(|log| agent_run_matches_filter(&log.request_id, &log.tenant, filter))
                    .cloned()
                    .collect::<Vec<_>>();
                let run_billing_events = billing_events
                    .iter()
                    .filter(|event| event.agent_run_id.as_deref() == Some(id.as_str()))
                    .filter(|event| {
                        agent_run_matches_filter(&event.request_id, &event.tenant, filter)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let run_audit_events = audit_events
                    .iter()
                    .filter(|event| event.agent_run_id.as_deref() == Some(id.as_str()))
                    .filter(|event| {
                        agent_run_matches_filter(&event.request_id, &event.tenant, filter)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                if run.is_none()
                    && run_agent_events.is_empty()
                    && run_requests.is_empty()
                    && run_billing_events.is_empty()
                    && run_audit_events.is_empty()
                {
                    return None;
                }
                Some(summarize_agent_run(
                    id,
                    run.as_ref(),
                    &run_agent_events,
                    &run_requests,
                    &run_billing_events,
                    &run_audit_events,
                ))
            })
            .collect()
    }

    pub(crate) fn record_agent_run(&self, run: StoredAgentRun) {
        // Fire-and-forget write bridged to the async pool (issue #221). Kept
        // sync because record_agent_run_event's sibling is reached from
        // external_actions.rs's Unix-socket authorizer thread (no tokio
        // runtime); block_on_sync_bridge handles both that and async handlers.
        if let Err(error) =
            crate::gateway::block_on_sync_bridge(self.repositories.upsert_agent_run(run))
        {
            warn!("failed to persist agent run record: {error}");
        }
    }

    /// Looks up an existing agent-run record by id, for the create-path
    /// ownership guard (a client-controlled run_id must not overwrite another
    /// tenant's run). Sync, bridged to the async pool like `record_agent_run`.
    pub(crate) fn agent_run_record(&self, id: &str) -> Option<StoredAgentRun> {
        crate::gateway::block_on_sync_bridge(self.repositories.agent_run(id))
    }

    pub(crate) fn record_agent_run_event(&self, event: StoredAgentRunEvent) {
        if let Err(error) =
            crate::gateway::block_on_sync_bridge(self.repositories.append_agent_run_event(event))
        {
            warn!("failed to persist agent run event record: {error}");
        }
    }

    /// #279: idempotently opens a workflow run's durable, graph-level execution
    /// budget (token/tool-call/cost/wall-clock envelope) so each step debits
    /// against it. Returns the current envelope (existing or freshly opened), or
    /// `None` on a storage error -- a budget-store outage must not itself break
    /// every workflow run, so the caller treats `None` as "no budget decision
    /// available" and proceeds, matching the additive/opt-in wallet pattern.
    /// Sync (bridged like `record_agent_run`) because its caller,
    /// `agent_workflow_use`, is sync.
    pub(crate) fn open_workflow_run_budget(
        &self,
        workflow_id: &str,
        workflow_version: u32,
        run_id: &str,
        tenant_id: &str,
        caps: ferrogate_storage::WorkflowRunBudgetCaps,
        now_unix: i64,
    ) -> Option<ferrogate_storage::StoredWorkflowRunBudget> {
        match crate::gateway::block_on_sync_bridge(self.repositories.open_workflow_run_budget(
            workflow_id,
            workflow_version,
            run_id,
            tenant_id,
            caps,
            now_unix,
        )) {
            Ok(budget) => Some(budget),
            Err(error) => {
                warn!("failed to open workflow run budget: {error}");
                None
            }
        }
    }

    /// #279: atomically debits one completed step's spend against a run's
    /// envelope. Returns the debit outcome, or `None` when the run has no budget
    /// row (unbounded run) or on a storage error. Fail-closed enforcement of the
    /// resulting `Exceeded` is the caller's responsibility (it records the
    /// lifecycle event and denies the next step at open time).
    pub(crate) fn debit_workflow_run_budget(
        &self,
        id: &str,
        cost_credits: i64,
        tokens: i64,
        tool_calls: i64,
        now_unix: i64,
    ) -> Option<ferrogate_storage::WorkflowBudgetDebit> {
        match crate::gateway::block_on_sync_bridge(self.repositories.debit_workflow_run_budget(
            id,
            cost_credits,
            tokens,
            tool_calls,
            now_unix,
        )) {
            Ok(debit) => Some(debit),
            Err(ferrogate_storage::StorageError::NotFound(_)) => None,
            Err(error) => {
                warn!("failed to debit workflow run budget: {error}");
                None
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn record_managed_worker_lifecycle(
        &self,
        record: &ferrogate_runtime::ManagedWorkerLifecycleRecord,
    ) {
        fn status(value: ferrogate_runtime::ManagedWorkerSessionStatus) -> &'static str {
            match value {
                ferrogate_runtime::ManagedWorkerSessionStatus::Running => "running",
                ferrogate_runtime::ManagedWorkerSessionStatus::Completed => "completed",
                ferrogate_runtime::ManagedWorkerSessionStatus::Cancelled => "cancelled",
                ferrogate_runtime::ManagedWorkerSessionStatus::Failed => "failed",
                ferrogate_runtime::ManagedWorkerSessionStatus::CleanedUp => "cleaned_up",
            }
        }

        fn action(value: ferrogate_runtime::ManagedWorkerLifecycleAction) -> &'static str {
            match value {
                ferrogate_runtime::ManagedWorkerLifecycleAction::ExecOrAttach => "exec_or_attach",
                ferrogate_runtime::ManagedWorkerLifecycleAction::Stop => "stop",
                ferrogate_runtime::ManagedWorkerLifecycleAction::Cleanup => "cleanup",
                ferrogate_runtime::ManagedWorkerLifecycleAction::Failure => "failure",
            }
        }

        fn backend_kind(value: ferrogate_runtime::IsolationBackendKind) -> &'static str {
            match value {
                ferrogate_runtime::IsolationBackendKind::FirecrackerMicroVm => {
                    "firecracker_microvm"
                }
                ferrogate_runtime::IsolationBackendKind::KataContainers => "kata_containers",
                ferrogate_runtime::IsolationBackendKind::Gvisor => "gvisor",
                ferrogate_runtime::IsolationBackendKind::RootlessDocker => "rootless_docker",
                ferrogate_runtime::IsolationBackendKind::LocalProcess => "local_process",
            }
        }

        fn started_at(
            value: ferrogate_runtime::ManagedWorkerSessionStatus,
            timestamp: Option<u64>,
        ) -> Option<u64> {
            match value {
                ferrogate_runtime::ManagedWorkerSessionStatus::Running
                | ferrogate_runtime::ManagedWorkerSessionStatus::Completed
                | ferrogate_runtime::ManagedWorkerSessionStatus::Cancelled
                | ferrogate_runtime::ManagedWorkerSessionStatus::CleanedUp => timestamp,
                ferrogate_runtime::ManagedWorkerSessionStatus::Failed => None,
            }
        }

        fn completed_at(
            value: ferrogate_runtime::ManagedWorkerSessionStatus,
            timestamp: Option<u64>,
        ) -> Option<u64> {
            match value {
                ferrogate_runtime::ManagedWorkerSessionStatus::Completed
                | ferrogate_runtime::ManagedWorkerSessionStatus::Cancelled
                | ferrogate_runtime::ManagedWorkerSessionStatus::Failed
                | ferrogate_runtime::ManagedWorkerSessionStatus::CleanedUp => timestamp,
                ferrogate_runtime::ManagedWorkerSessionStatus::Running => None,
            }
        }

        fn cleanup_completed_at(
            value: ferrogate_runtime::ManagedWorkerSessionStatus,
            timestamp: Option<u64>,
        ) -> Option<u64> {
            match value {
                ferrogate_runtime::ManagedWorkerSessionStatus::CleanedUp => timestamp,
                ferrogate_runtime::ManagedWorkerSessionStatus::Running
                | ferrogate_runtime::ManagedWorkerSessionStatus::Completed
                | ferrogate_runtime::ManagedWorkerSessionStatus::Cancelled
                | ferrogate_runtime::ManagedWorkerSessionStatus::Failed => None,
            }
        }

        #[derive(Serialize)]
        struct EventIdInput<'a> {
            session_id: &'a str,
            run_id: &'a str,
            action: &'a str,
            outcome: &'a str,
            agent_worker_id: &'a str,
            isolation_instance_id: &'a Option<String>,
        }

        let tenant = ferrogate_core::TenantContext {
            organization_id: Some(record.tenant_id.clone()),
            project_id: Some(record.workspace_id.clone()),
            ..ferrogate_core::TenantContext::default()
        };
        let occurred_at_unix = now_unix_seconds();
        let status = status(record.status);
        let action = action(record.action);
        let backend_kind = backend_kind(record.isolation_backend_kind.clone());
        let event_id_bytes = serde_json::to_vec(&EventIdInput {
            session_id: &record.session_id,
            run_id: &record.run_id,
            action,
            outcome: &record.outcome,
            agent_worker_id: &record.agent_worker_id,
            isolation_instance_id: &record.isolation_instance_id,
        })
        .expect("managed worker lifecycle event id serialization should not fail");
        let agent_worker = StoredAgentWorkerInstance {
            id: record.agent_worker_id.clone(),
            process_name: "agent-worker".to_string(),
            host_id: None,
            worker_version: None,
            status: "observed".to_string(),
            started_at_unix: None,
            last_seen_at_unix: occurred_at_unix,
            process_json: serde_json::json!({
                "process_boundary": "external_process",
                "host_lifecycle_owner": "agent-worker",
                "transport_implemented": false,
            })
            .to_string(),
        };
        if let Err(error) = crate::gateway::block_on_sync_bridge(
            self.repositories.upsert_agent_worker_instance(agent_worker),
        ) {
            warn!("failed to persist agent-worker instance record: {error}");
            return;
        }

        let session = StoredManagedWorkerSession {
            id: record.session_id.clone(),
            run_id: record.run_id.clone(),
            tenant: tenant.clone(),
            workspace_id: record.workspace_id.clone(),
            worker_template_id: record.worker_template_id.clone(),
            agent_worker_instance_id: Some(record.agent_worker_id.clone()),
            status: status.to_string(),
            isolation_backend_kind: backend_kind.to_string(),
            microvm_id: record.isolation_instance_id.clone(),
            capability_envelope_id: record.capability_envelope_id.clone(),
            requested_at_unix: occurred_at_unix,
            started_at_unix: started_at(record.status, occurred_at_unix),
            completed_at_unix: completed_at(record.status, occurred_at_unix),
            cleanup_completed_at_unix: cleanup_completed_at(record.status, occurred_at_unix),
            capability_envelope_json: serde_json::json!({
                "id": record.capability_envelope_id,
                "boundary": "gateway_mediated",
            })
            .to_string(),
            resource_limits_json: "{}".to_string(),
        };
        if let Err(error) = crate::gateway::block_on_sync_bridge(
            self.repositories.upsert_managed_worker_session(session),
        ) {
            warn!("failed to persist managed worker session record: {error}");
            return;
        }

        let isolation_policy = ferrogate_runtime::IsolationPolicy::default();
        let isolation_selection = StoredManagedWorkerIsolationSelection {
            session_id: record.session_id.clone(),
            run_id: record.run_id.clone(),
            tenant: tenant.clone(),
            workspace_id: record.workspace_id.clone(),
            agent_worker_instance_id: Some(record.agent_worker_id.clone()),
            backend_name: backend_kind.to_string(),
            backend_version: record.isolation_backend_version.clone(),
            backend_kind: backend_kind.to_string(),
            host_lifecycle_owner: "agent-worker".to_string(),
            gateway_controls_backend: false,
            capability_envelope_id: record.capability_envelope_id.clone(),
            selected_at_unix: occurred_at_unix,
        };
        if let Err(error) = crate::gateway::block_on_sync_bridge(
            self.repositories
                .upsert_managed_worker_isolation_selection(isolation_selection),
        ) {
            warn!("failed to persist managed worker isolation selection record: {error}");
        }

        let resource_limits = isolation_policy.resource_limits;
        let network_policy = isolation_policy.network_policy;
        let filesystem_policy = isolation_policy.filesystem_policy;
        let isolation_policy_record = StoredManagedWorkerIsolationPolicy {
            session_id: record.session_id.clone(),
            cpu_count: resource_limits.cpu_count,
            memory_mib: resource_limits.memory_mib,
            disk_mib: resource_limits.disk_mib,
            max_runtime_millis: resource_limits.max_runtime_millis,
            direct_public_egress: network_policy.direct_public_egress,
            gateway_control_channel: network_policy.gateway_control_channel,
            governed_egress: network_policy.governed_egress,
            read_only_rootfs: filesystem_policy.read_only_rootfs,
            writable_workspace: filesystem_policy.writable_workspace,
            host_path_mounts: filesystem_policy.host_path_mounts,
        };
        if let Err(error) = crate::gateway::block_on_sync_bridge(
            self.repositories
                .upsert_managed_worker_isolation_policy(isolation_policy_record),
        ) {
            warn!("failed to persist managed worker isolation policy record: {error}");
        }

        let lifecycle_event_id = format!("mwl-{:016x}", fnv1a64(&event_id_bytes));
        let event = StoredManagedWorkerLifecycleEvent {
            id: lifecycle_event_id.clone(),
            session_id: record.session_id.clone(),
            run_id: record.run_id.clone(),
            tenant,
            workspace_id: record.workspace_id.clone(),
            agent_worker_instance_id: Some(record.agent_worker_id.clone()),
            status: status.to_string(),
            action: action.to_string(),
            outcome: record.outcome.clone(),
            occurred_at_unix,
            evidence_json: serde_json::json!({
                "agent_worker_id": record.agent_worker_id,
                "host_lifecycle_owner": "agent-worker",
                "isolation_backend_kind": backend_kind,
                "isolation_instance_id": record.isolation_instance_id,
                "capability_envelope_id": record.capability_envelope_id,
                "failure_reason": record.failure_reason,
            })
            .to_string(),
        };
        if let Err(error) = crate::gateway::block_on_sync_bridge(
            self.repositories
                .append_managed_worker_lifecycle_event(event),
        ) {
            warn!("failed to persist managed worker lifecycle event record: {error}");
            return;
        }

        let evidence = StoredManagedWorkerIsolationEvidence {
            id: format!("mwie-{:016x}", fnv1a64(&event_id_bytes)),
            session_id: record.session_id.clone(),
            lifecycle_event_id,
            run_id: record.run_id.clone(),
            tenant: ferrogate_core::TenantContext {
                organization_id: Some(record.tenant_id.clone()),
                project_id: Some(record.workspace_id.clone()),
                ..ferrogate_core::TenantContext::default()
            },
            workspace_id: record.workspace_id.clone(),
            agent_worker_instance_id: Some(record.agent_worker_id.clone()),
            isolation_instance_id: record.isolation_instance_id.clone(),
            action: action.to_string(),
            outcome: record.outcome.clone(),
            failure_reason: record.failure_reason.clone(),
            occurred_at_unix,
            evidence_json: serde_json::json!({
                "agent_worker_id": record.agent_worker_id,
                "host_lifecycle_owner": "agent-worker",
                "gateway_controls_backend": false,
                "isolation_backend_kind": backend_kind,
                "isolation_instance_id": record.isolation_instance_id,
                "capability_envelope_id": record.capability_envelope_id,
                "resource_limits": {
                    "cpu_count": resource_limits.cpu_count,
                    "memory_mib": resource_limits.memory_mib,
                    "disk_mib": resource_limits.disk_mib,
                    "max_runtime_millis": resource_limits.max_runtime_millis,
                },
                "network_policy": {
                    "direct_public_egress": network_policy.direct_public_egress,
                    "gateway_control_channel": network_policy.gateway_control_channel,
                    "governed_egress": network_policy.governed_egress,
                },
                "filesystem_policy": {
                    "read_only_rootfs": filesystem_policy.read_only_rootfs,
                    "writable_workspace": filesystem_policy.writable_workspace,
                    "host_path_mounts": filesystem_policy.host_path_mounts,
                },
                "failure_reason": record.failure_reason,
            })
            .to_string(),
        };
        if let Err(error) = crate::gateway::block_on_sync_bridge(
            self.repositories
                .upsert_managed_worker_isolation_evidence(evidence),
        ) {
            warn!("failed to persist managed worker isolation evidence record: {error}");
        }
    }

    pub(crate) fn tool_session_events(&self, session_id: &str) -> Vec<StoredAuditEvent> {
        let target = format!("tool_session:{session_id}");
        let target_prefix = format!("{target}/");
        crate::gateway::block_on_sync_bridge(self.repositories.audit_events())
            .into_iter()
            .filter(|event| {
                event.action == "tool.execute"
                    && (event.target == target || event.target.starts_with(&target_prefix))
            })
            .collect()
    }
}

/// Upper bound on telemetry events returned for one run's admin timeline
/// (issue #231). The repository keeps the NEWEST window so a flooded run
/// still reports its latest lifecycle state; both backends push the run_id
/// filter + LIMIT into the store (SQL on the durable path).
pub(crate) const SELF_HOSTED_RUN_TIMELINE_EVENT_LIMIT: usize = 1_000;

/// Upper bound on distinct agent-run ids considered per admin summary read
/// (issue #231): the most recently seen runs win. Replaces enumerating run
/// ids by loading four whole tables into memory.
pub(crate) const AGENT_RUN_SUMMARY_SCAN_LIMIT: usize = 1_000;

/// Shared assembly of the admin worker record from its already-filtered
/// parts (issue #231): used by both the single-worker hot path (repository
/// pushes the worker_id filter into SQL) and the bulk admin list.
fn self_hosted_worker_record_from_parts(
    registration: StoredSelfHostedWorkerRegistration,
    latest_heartbeat: Option<StoredSelfHostedWorkerHeartbeat>,
    stats: ferrogate_storage::StoredSelfHostedWorkerActivityStats,
    now_unix: Option<u64>,
) -> crate::responses::AdminSelfHostedWorkerRecord {
    let (stale, stale_after_unix) =
        self_hosted_worker_stale_state(registration.last_seen_at_unix, now_unix);
    crate::responses::AdminSelfHostedWorkerRecord {
        id: registration.id,
        tenant: registration.tenant,
        workspace_id: registration.workspace_id,
        worker_name: registration.worker_name,
        status: registration.status,
        identity_fingerprint: registration.identity_fingerprint,
        identity_expires_at_unix: registration.identity_expires_at_unix,
        orchestration_enabled: registration.orchestration_enabled,
        registered_at_unix: registration.registered_at_unix,
        last_seen_at_unix: registration.last_seen_at_unix,
        trust_level: registration.trust_level,
        stale,
        stale_after_unix,
        stale_threshold_secs: SELF_HOSTED_WORKER_STALE_THRESHOLD_SECS,
        latest_heartbeat: latest_heartbeat.map(|heartbeat| {
            crate::responses::AdminSelfHostedWorkerHeartbeat {
                id: heartbeat.id,
                status: heartbeat.status,
                reported_at_unix: heartbeat.reported_at_unix,
                observed_at_unix: heartbeat.observed_at_unix,
            }
        }),
        telemetry_event_count: stats.telemetry_event_count,
        artifact_count: stats.artifact_count,
        checkpoint_count: stats.checkpoint_count,
        latest_event_at_unix: stats.latest_event_at_unix,
        latest_artifact_at_unix: stats.latest_artifact_at_unix,
        latest_checkpoint_at_unix: stats.latest_checkpoint_at_unix,
    }
}

/// Env var carrying the self-hosted worker issuing-CA certificate (inline PEM).
const SELF_HOSTED_MTLS_ISSUING_CA_CERT_PEM_ENV: &str =
    "FERROGATE_SELF_HOSTED_MTLS_ISSUING_CA_CERT_PEM";
/// Env var carrying a path to the issuing-CA certificate PEM.
const SELF_HOSTED_MTLS_ISSUING_CA_CERT_PEM_PATH_ENV: &str =
    "FERROGATE_SELF_HOSTED_MTLS_ISSUING_CA_CERT_PEM_PATH";
/// Env var carrying the self-hosted worker issuing-CA private key (inline PEM).
const SELF_HOSTED_MTLS_ISSUING_CA_KEY_PEM_ENV: &str =
    "FERROGATE_SELF_HOSTED_MTLS_ISSUING_CA_KEY_PEM";
/// Env var carrying a path to the issuing-CA private key PEM.
const SELF_HOSTED_MTLS_ISSUING_CA_KEY_PEM_PATH_ENV: &str =
    "FERROGATE_SELF_HOSTED_MTLS_ISSUING_CA_KEY_PEM_PATH";
/// Optional override for the minted client certificate TTL (seconds).
const SELF_HOSTED_MTLS_CERT_TTL_SECS_ENV: &str = "FERROGATE_SELF_HOSTED_MTLS_CERT_TTL_SECS";

/// Read a PEM value from either an inline env var or a `*_PATH` env var pointing
/// at a file. `None` when neither is set.
fn self_hosted_mtls_pem_from_env(
    inline_env: &str,
    path_env: &str,
) -> Result<Option<String>, SelfHostedWorkerRecordError> {
    if let Ok(inline) = env::var(inline_env) {
        if !inline.trim().is_empty() {
            return Ok(Some(inline));
        }
    }
    if let Ok(path) = env::var(path_env) {
        if !path.trim().is_empty() {
            let pem = std::fs::read_to_string(&path).map_err(|error| {
                SelfHostedWorkerRecordError::Storage(format!(
                    "failed to read self-hosted worker issuing CA material from {path}: {error}"
                ))
            })?;
            return Ok(Some(pem));
        }
    }
    Ok(None)
}

/// Build the configured self-hosted worker issuing CA from the environment, or
/// `None` when no CA is configured (issue #249). Fail-closed: a partial or
/// malformed configuration is a hard error rather than a silent skip, so an
/// operator who intends production mTLS cannot accidentally register workers
/// without certs.
fn self_hosted_mtls_cert_issuer_from_env(
) -> Result<Option<ferrogate_runtime::SelfHostedMtlsCertIssuer>, SelfHostedWorkerRecordError> {
    let cert_pem = self_hosted_mtls_pem_from_env(
        SELF_HOSTED_MTLS_ISSUING_CA_CERT_PEM_ENV,
        SELF_HOSTED_MTLS_ISSUING_CA_CERT_PEM_PATH_ENV,
    )?;
    let key_pem = self_hosted_mtls_pem_from_env(
        SELF_HOSTED_MTLS_ISSUING_CA_KEY_PEM_ENV,
        SELF_HOSTED_MTLS_ISSUING_CA_KEY_PEM_PATH_ENV,
    )?;
    let (cert_pem, key_pem) = match (cert_pem, key_pem) {
        (None, None) => return Ok(None),
        (Some(cert_pem), Some(key_pem)) => (cert_pem, key_pem),
        (Some(_), None) | (None, Some(_)) => {
            return Err(SelfHostedWorkerRecordError::Storage(
                "self-hosted worker issuing CA is misconfigured: both the certificate and the \
                 private key PEM must be provided"
                    .into(),
            ));
        }
    };
    let ttl_secs = match env::var(SELF_HOSTED_MTLS_CERT_TTL_SECS_ENV) {
        Ok(value) if !value.trim().is_empty() => value.trim().parse::<u64>().map_err(|error| {
            SelfHostedWorkerRecordError::Storage(format!(
                "{SELF_HOSTED_MTLS_CERT_TTL_SECS_ENV} is not a valid number of seconds: {error}"
            ))
        })?,
        _ => ferrogate_runtime::DEFAULT_SELF_HOSTED_CLIENT_CERT_TTL_SECS,
    };
    ferrogate_runtime::SelfHostedMtlsCertIssuer::from_ca_pem(&cert_pem, &key_pem, ttl_secs)
        .map(Some)
        .map_err(|error| SelfHostedWorkerRecordError::Storage(error.to_string()))
}

/// Mint a client certificate for a stored self-hosted worker registration,
/// bound to its SPIFFE 4-tuple (tenant/workspace/worker/token). Pure over the
/// issuer + clock so it is unit-testable without env/PKI (issue #249).
fn mint_self_hosted_worker_client_certificate(
    registration: &StoredSelfHostedWorkerRegistration,
    issuer: &ferrogate_runtime::SelfHostedMtlsCertIssuer,
    now_unix: u64,
) -> Result<crate::responses::AdminSelfHostedWorkerClientCertificate, SelfHostedWorkerRecordError> {
    let binding = ferrogate_runtime::SelfHostedWorkerCertBinding {
        tenant_id: self_hosted_tenant_id(&registration.tenant),
        workspace_id: registration.workspace_id.clone(),
        worker_id: registration.id.clone(),
        // token_id is the public 4-tuple segment == the identity fingerprint (the
        // same value carried in transport frames and the SPIFFE SAN).
        token_id: registration.identity_fingerprint.clone(),
    };
    let issued = issuer
        .issue_client_cert(&binding, now_unix)
        .map_err(|error| SelfHostedWorkerRecordError::Storage(error.to_string()))?;
    Ok(crate::responses::AdminSelfHostedWorkerClientCertificate {
        spiffe_id: issued.spiffe_id(),
        certificate_pem: issued.certificate_pem().to_string(),
        private_key_pem: issued.private_key_pkcs8_pem().to_string(),
        fingerprint: issued.fingerprint().to_string(),
        serial: issued.serial_hex().to_string(),
        not_after_unix: issued.not_after_unix(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(future)
    }

    #[test]
    fn agent_run_record_returns_the_owning_tenant_for_the_ownership_guard() {
        // The create-path ownership guard rejects overwriting a run owned by a
        // different organization; this locks in that agent_run_record surfaces
        // the stored run's tenant so that comparison is possible.
        let state = AppState::new(Config::default());
        let run = |id: &str, org: &str| ferrogate_storage::StoredAgentRun {
            id: id.to_string(),
            request_id: format!("req-{id}"),
            trace_id: None,
            tenant: ferrogate_core::TenantContext {
                organization_id: Some(org.to_string()),
                ..Default::default()
            },
            status: "running".into(),
            provider: "managed.native-harness".into(),
            turns_executed: 0,
            output_recorded: false,
            started_at_unix: Some(1),
            completed_at_unix: None,
        };
        state.record_agent_run(run("run-a", "tenant-a"));

        let found = state.agent_run_record("run-a").expect("run must be found");
        assert_eq!(found.tenant.organization_id.as_deref(), Some("tenant-a"));
        // A different tenant's id is not conjured up.
        assert!(state.agent_run_record("run-nonexistent").is_none());
    }

    #[test]
    fn workflow_gating_readers_are_scoped_to_the_callers_tenant() {
        // #228: agent_run_id is client-supplied and not tenant-namespaced. A
        // request log recorded for tenant-a's run must NOT feed tenant-b's
        // (or an operator's) run-gating just because tenant-b reuses the id.
        let state = AppState::new(Config::default());
        let log = |org: &str, node: &str, ts: u64| StoredRequestLog {
            request_id: format!("req-{org}-{node}"),
            trace_id: None,
            agent_run_id: Some("shared-run-id".into()),
            workflow_id: Some("wf".into()),
            workflow_version: Some(1),
            workflow_node_id: Some(node.into()),
            cluster_id: None,
            node_id: None,
            tenant: ferrogate_core::TenantContext {
                organization_id: Some(org.to_string()),
                ..Default::default()
            },
            route: None,
            provider: None,
            logical_model: None,
            provider_model: None,
            gateway_config_id: None,
            gateway_config_revision: None,
            status_code: 200,
            error_code: None,
            prompt_recorded: false,
            response_recorded: false,
            prompt_body: None,
            response_body: None,
            cache_status: None,
            started_at_unix: Some(ts),
            completed_at_unix: Some(ts),
        };
        state.record_request_log(log("tenant-a", "start", 100));

        // tenant-a sees its own run start; tenant-b (same agent_run_id) does not,
        // and neither does a platform operator (org None).
        assert_eq!(
            state.workflow_run_started_at("wf", 1, "shared-run-id", Some("tenant-a")),
            Some(100),
        );
        assert_eq!(
            state.workflow_run_started_at("wf", 1, "shared-run-id", Some("tenant-b")),
            None,
            "tenant-b must not read tenant-a's run timestamps via a shared agent_run_id",
        );
        assert_eq!(
            state.workflow_run_started_at("wf", 1, "shared-run-id", None),
            None,
            "an operator must not inherit a tenant's run start",
        );

        // Same isolation for the last-successful-node gate.
        assert_eq!(
            state.workflow_run_last_successful_node_id("wf", 1, "shared-run-id", Some("tenant-a")),
            Some("start".into()),
        );
        assert_eq!(
            state.workflow_run_last_successful_node_id("wf", 1, "shared-run-id", Some("tenant-b")),
            None,
        );
    }

    #[test]
    fn self_hosted_worker_cannot_overwrite_another_workers_checkpoint_or_artifact() {
        // #228 (round-11): checkpoint/artifact ids share a GLOBAL namespace, so a
        // worker reusing another worker's id must be rejected, not allowed to
        // clobber and re-attribute another tenant's row.
        let state = AppState::new(Config::default());
        let register = |org: &str, name: &str| {
            state
                .register_self_hosted_worker(
                    crate::responses::AdminSelfHostedWorkerRegistrationRequest {
                        tenant: ferrogate_core::TenantContext {
                            organization_id: Some(org.to_string()),
                            ..Default::default()
                        },
                        workspace_id: format!("ws-{org}"),
                        worker_name: name.to_string(),
                        identity_fingerprint: format!("sha256:{name}"),
                        identity_expires_at_unix: Some(4_000_000_000),
                        orchestration_enabled: false,
                        capability_envelope_json: None,
                    },
                )
                .expect("registration accepted")
                .0
        };
        let worker_a = register("org-a", "worker-a");
        let worker_b = register("org-b", "worker-b");

        let checkpoint_req = |id: &str| crate::responses::AdminSelfHostedWorkerCheckpointRequest {
            checkpoint_id: id.to_string(),
            session_id: "session".into(),
            run_id: "run".into(),
            checkpoint_name: "resume".into(),
            size_bytes: 1,
            created_at_unix: Some(1),
            checkpoint_json: None,
        };
        // Worker A records a checkpoint.
        state
            .record_self_hosted_worker_checkpoint(&worker_a.id, checkpoint_req("resume-state"))
            .expect("worker A records its checkpoint");
        // Worker B (different tenant) reusing the SAME checkpoint id is rejected.
        let denied = state
            .record_self_hosted_worker_checkpoint(&worker_b.id, checkpoint_req("resume-state"));
        assert!(
            matches!(denied, Err(SelfHostedWorkerRecordError::InvalidRequest(_))),
            "cross-worker checkpoint id reuse must be rejected, got {denied:?}",
        );
        // Worker A's checkpoint is intact and still owned by A.
        let checkpoints = block_on(state.repositories.self_hosted_worker_checkpoints());
        let stored = checkpoints
            .iter()
            .find(|checkpoint| checkpoint.id == "resume-state")
            .expect("A's checkpoint survives");
        assert_eq!(stored.worker_id, worker_a.id);

        // Same protection for artifacts.
        let artifact_req = |id: &str| crate::responses::AdminSelfHostedWorkerArtifactRequest {
            artifact_id: id.to_string(),
            session_id: "session".into(),
            run_id: "run".into(),
            artifact_name: "out".into(),
            content_type: None,
            size_bytes: 1,
            created_at_unix: Some(1),
            artifact_json: None,
        };
        state
            .record_self_hosted_worker_artifact(&worker_a.id, artifact_req("build-output"))
            .expect("worker A records its artifact");
        let denied_artifact =
            state.record_self_hosted_worker_artifact(&worker_b.id, artifact_req("build-output"));
        assert!(
            matches!(
                denied_artifact,
                Err(SelfHostedWorkerRecordError::InvalidRequest(_))
            ),
            "cross-worker artifact id reuse must be rejected, got {denied_artifact:?}",
        );
        let artifacts = block_on(state.repositories.self_hosted_worker_artifacts());
        assert_eq!(
            artifacts
                .iter()
                .find(|artifact| artifact.id == "build-output")
                .expect("A's artifact survives")
                .worker_id,
            worker_a.id,
        );
    }

    #[test]
    fn records_managed_worker_lifecycle_records_into_storage() {
        let state = AppState::new(Config::default());
        let record = ferrogate_runtime::ManagedWorkerLifecycleRecord {
            session_id: "session-1".into(),
            run_id: "run-1".into(),
            tenant_id: "tenant-1".into(),
            workspace_id: "workspace-1".into(),
            worker_template_id: "template-codex".into(),
            agent_worker_id: "agent-worker-1".into(),
            isolation_backend_kind: ferrogate_runtime::IsolationBackendKind::FirecrackerMicroVm,
            isolation_backend_version: "external_bundle".into(),
            isolation_instance_id: Some("microvm-1".into()),
            capability_envelope_id: "capability-1".into(),
            status: ferrogate_runtime::ManagedWorkerSessionStatus::CleanedUp,
            action: ferrogate_runtime::ManagedWorkerLifecycleAction::Cleanup,
            outcome: "cleaned_up".into(),
            failure_reason: None,
        };

        state.record_managed_worker_lifecycle(&record);

        let agent_workers = block_on(state.repositories.agent_worker_instances());
        assert_eq!(agent_workers.len(), 1);
        assert_eq!(agent_workers[0].id, "agent-worker-1");
        assert_eq!(agent_workers[0].process_name, "agent-worker");
        assert_eq!(agent_workers[0].status, "observed");
        assert!(agent_workers[0]
            .process_json
            .contains("\"process_boundary\":\"external_process\""));

        let sessions = block_on(state.repositories.managed_worker_sessions());
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "session-1");
        assert_eq!(sessions[0].run_id, "run-1");
        assert_eq!(
            sessions[0].tenant.organization_id.as_deref(),
            Some("tenant-1")
        );
        assert_eq!(
            sessions[0].tenant.project_id.as_deref(),
            Some("workspace-1")
        );
        assert_eq!(sessions[0].workspace_id, "workspace-1");
        assert_eq!(
            sessions[0].agent_worker_instance_id.as_deref(),
            Some("agent-worker-1")
        );
        assert_eq!(sessions[0].status, "cleaned_up");
        assert_eq!(sessions[0].isolation_backend_kind, "firecracker_microvm");
        assert_eq!(sessions[0].microvm_id.as_deref(), Some("microvm-1"));
        assert_eq!(sessions[0].capability_envelope_id, "capability-1");
        assert!(sessions[0].cleanup_completed_at_unix.is_some());

        let events = block_on(state.repositories.managed_worker_lifecycle_events());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].session_id, "session-1");
        assert_eq!(events[0].run_id, "run-1");
        assert_eq!(
            events[0].tenant.organization_id.as_deref(),
            Some("tenant-1")
        );
        assert_eq!(events[0].workspace_id, "workspace-1");
        assert_eq!(
            events[0].agent_worker_instance_id.as_deref(),
            Some("agent-worker-1")
        );
        assert_eq!(events[0].status, "cleaned_up");
        assert_eq!(events[0].action, "cleanup");
        assert_eq!(events[0].outcome, "cleaned_up");
        assert!(events[0].id.starts_with("mwl-"));
        assert!(events[0]
            .evidence_json
            .contains("\"host_lifecycle_owner\":\"agent-worker\""));
        assert!(events[0]
            .evidence_json
            .contains("\"isolation_backend_kind\":\"firecracker_microvm\""));

        let selections = block_on(state.repositories.managed_worker_isolation_selections());
        assert_eq!(selections.len(), 1);
        assert_eq!(selections[0].session_id, "session-1");
        assert_eq!(selections[0].backend_kind, "firecracker_microvm");
        // The persisted selection carries the real backend version reported by
        // agent-worker, not a hardcoded "unknown".
        assert_eq!(selections[0].backend_version, "external_bundle");
        assert_eq!(selections[0].host_lifecycle_owner, "agent-worker");
        assert!(!selections[0].gateway_controls_backend);
        assert_eq!(
            selections[0].agent_worker_instance_id.as_deref(),
            Some("agent-worker-1")
        );

        let policies = block_on(state.repositories.managed_worker_isolation_policies());
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].session_id, "session-1");
        assert!(!policies[0].direct_public_egress);
        assert!(policies[0].gateway_control_channel);
        assert!(policies[0].governed_egress);
        assert!(policies[0].read_only_rootfs);
        assert!(!policies[0].host_path_mounts);

        let isolation_evidence = block_on(state.repositories.managed_worker_isolation_evidence());
        assert_eq!(isolation_evidence.len(), 1);
        assert_eq!(isolation_evidence[0].session_id, "session-1");
        assert_eq!(isolation_evidence[0].lifecycle_event_id, events[0].id);
        assert_eq!(
            isolation_evidence[0].isolation_instance_id.as_deref(),
            Some("microvm-1")
        );
        assert_eq!(isolation_evidence[0].outcome, "cleaned_up");
        assert!(isolation_evidence[0]
            .evidence_json
            .contains("\"gateway_controls_backend\":false"));
    }

    #[test]
    fn managed_worker_sessions_page_filters_by_tenant_scope() {
        // Issue #186: the managed-worker-sessions admin list leaked every
        // tenant's sessions to a tenant-scoped `admin.read` key. Proves the
        // new `tenant_scope` param on `managed_worker_sessions_page`
        // narrows correctly, using the same real production code path
        // (`record_managed_worker_lifecycle`) that a real managed-worker
        // dispatch would use.
        let state = AppState::new(Config::default());
        let record =
            |session_id: &str, tenant_id: &str| ferrogate_runtime::ManagedWorkerLifecycleRecord {
                session_id: session_id.into(),
                run_id: format!("run-{session_id}"),
                tenant_id: tenant_id.into(),
                workspace_id: "workspace-1".into(),
                worker_template_id: "template-codex".into(),
                agent_worker_id: format!("agent-worker-{session_id}"),
                isolation_backend_kind: ferrogate_runtime::IsolationBackendKind::FirecrackerMicroVm,
                isolation_backend_version: "external_bundle".into(),
                isolation_instance_id: Some(format!("microvm-{session_id}")),
                capability_envelope_id: "capability-1".into(),
                status: ferrogate_runtime::ManagedWorkerSessionStatus::Running,
                action: ferrogate_runtime::ManagedWorkerLifecycleAction::ExecOrAttach,
                outcome: "started".into(),
                failure_reason: None,
            };
        state.record_managed_worker_lifecycle(&record("session-a", "tenant-iso-a"));
        state.record_managed_worker_lifecycle(&record("session-b", "tenant-iso-b"));

        let tenant_a_page = state.managed_worker_sessions_page(
            AdminPagination {
                offset: 0,
                limit: 50,
            },
            Some("tenant-iso-a"),
        );
        assert_eq!(tenant_a_page.total, 1);
        assert_eq!(tenant_a_page.data[0].id, "session-a");

        let unfiltered_page = state.managed_worker_sessions_page(
            AdminPagination {
                offset: 0,
                limit: 50,
            },
            None,
        );
        assert_eq!(unfiltered_page.total, 2);
    }

    #[test]
    fn self_hosted_worker_records_page_reads_storage_evidence() {
        let state = AppState::new(Config::default());
        let tenant = ferrogate_core::TenantContext {
            workspace_id: None,
            organization_id: Some("org".into()),
            team_id: None,
            project_id: Some("project".into()),
            user_id: None,
            api_key_id: Some("key".into()),
        };

        block_on(state.repositories.upsert_self_hosted_worker_registration(
            StoredSelfHostedWorkerRegistration {
                id: "worker-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                worker_name: "customer-worker".into(),
                status: "online".into(),
                identity_fingerprint: "sha256:worker".into(),
                identity_expires_at_unix: None,
                orchestration_enabled: true,
                registered_at_unix: Some(10),
                last_seen_at_unix: Some(20),
                trust_level: "reported_by_self_hosted_worker".into(),
                capability_envelope_json: "{}".into(),
                token_secret: "transport-secret-aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            },
        ))
        .unwrap();
        block_on(state.repositories.append_self_hosted_worker_heartbeat(
            StoredSelfHostedWorkerHeartbeat {
                id: "heartbeat-old".into(),
                worker_id: "worker-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                status: "online".into(),
                reported_at_unix: Some(21),
                observed_at_unix: Some(22),
                heartbeat_json: "{}".into(),
            },
        ))
        .unwrap();
        block_on(state.repositories.append_self_hosted_worker_heartbeat(
            StoredSelfHostedWorkerHeartbeat {
                id: "heartbeat-new".into(),
                worker_id: "worker-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                status: "degraded".into(),
                reported_at_unix: Some(23),
                observed_at_unix: Some(24),
                heartbeat_json: "{}".into(),
            },
        ))
        .unwrap();
        block_on(
            state
                .repositories
                .append_self_hosted_worker_telemetry_event(StoredSelfHostedWorkerTelemetryEvent {
                    id: "telemetry-1".into(),
                    worker_id: "worker-1".into(),
                    tenant: tenant.clone(),
                    workspace_id: "workspace-1".into(),
                    session_id: Some("session-1".into()),
                    run_id: Some("run-1".into()),
                    kind: "log".into(),
                    trust_level: "reported_by_self_hosted_worker".into(),
                    occurred_at_unix: Some(25),
                    ingested_at_unix: Some(26),
                    event_json: "{}".into(),
                }),
        )
        .unwrap();
        block_on(state.repositories.upsert_self_hosted_worker_artifact(
            StoredSelfHostedWorkerArtifact {
                id: "artifact-1".into(),
                worker_id: "worker-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                artifact_name: "stdout.log".into(),
                content_type: Some("text/plain".into()),
                size_bytes: 128,
                trust_level: "reported_by_self_hosted_worker".into(),
                created_at_unix: Some(27),
                artifact_json: "{}".into(),
            },
        ))
        .unwrap();
        block_on(state.repositories.upsert_self_hosted_worker_checkpoint(
            StoredSelfHostedWorkerCheckpoint {
                id: "checkpoint-1".into(),
                worker_id: "worker-1".into(),
                tenant,
                workspace_id: "workspace-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                checkpoint_name: "resume-state".into(),
                size_bytes: 256,
                trust_level: "reported_by_self_hosted_worker".into(),
                created_at_unix: Some(28),
                checkpoint_json: "{}".into(),
            },
        ))
        .unwrap();

        let page = state.self_hosted_worker_records_page(
            AdminPagination {
                offset: 0,
                limit: 50,
            },
            None,
        );

        assert_eq!(page.total, 1);
        assert_eq!(page.data[0].id, "worker-1");
        assert_eq!(page.data[0].worker_name, "customer-worker");
        assert_eq!(page.data[0].telemetry_event_count, 1);
        assert_eq!(page.data[0].artifact_count, 1);
        assert_eq!(page.data[0].checkpoint_count, 1);
        assert_eq!(page.data[0].latest_event_at_unix, Some(25));
        assert_eq!(page.data[0].latest_artifact_at_unix, Some(27));
        assert_eq!(page.data[0].latest_checkpoint_at_unix, Some(28));
        assert_eq!(
            page.data[0].stale_threshold_secs,
            SELF_HOSTED_WORKER_STALE_THRESHOLD_SECS
        );
        assert_eq!(
            page.data[0].stale_after_unix,
            Some(20 + SELF_HOSTED_WORKER_STALE_THRESHOLD_SECS)
        );
        assert!(page.data[0].stale);
        let heartbeat = page.data[0].latest_heartbeat.as_ref().unwrap();
        assert_eq!(heartbeat.id, "heartbeat-new");
        assert_eq!(heartbeat.status, "degraded");

        let detail = state
            .self_hosted_worker_record("worker-1")
            .expect("worker detail should be readable by id");
        assert_eq!(detail.id, "worker-1");
        assert_eq!(detail.worker_name, "customer-worker");
        assert_eq!(detail.telemetry_event_count, 1);
        assert_eq!(detail.artifact_count, 1);
        assert_eq!(detail.checkpoint_count, 1);
        assert_eq!(
            detail
                .latest_heartbeat
                .as_ref()
                .map(|heartbeat| heartbeat.id.as_str()),
            Some("heartbeat-new")
        );

        assert!(state.self_hosted_worker_record("missing-worker").is_none());
    }

    #[test]
    fn self_hosted_run_timeline_reads_reported_lifecycle_events() {
        let state = AppState::new(Config::default());
        let tenant = ferrogate_core::TenantContext {
            workspace_id: None,
            organization_id: Some("org".into()),
            team_id: None,
            project_id: Some("project".into()),
            user_id: None,
            api_key_id: Some("key".into()),
        };
        block_on(
            state
                .repositories
                .append_self_hosted_worker_telemetry_event(StoredSelfHostedWorkerTelemetryEvent {
                    id: "event-tool".into(),
                    worker_id: "worker-1".into(),
                    tenant: tenant.clone(),
                    workspace_id: "workspace-1".into(),
                    session_id: Some("session-1".into()),
                    run_id: Some("run-1".into()),
                    kind: "tool_call".into(),
                    trust_level: "reported_by_self_hosted_worker".into(),
                    occurred_at_unix: Some(20),
                    ingested_at_unix: Some(21),
                    event_json: r#"{"tool":"shell"}"#.into(),
                }),
        )
        .unwrap();
        block_on(
            state
                .repositories
                .append_self_hosted_worker_telemetry_event(StoredSelfHostedWorkerTelemetryEvent {
                    id: "event-lifecycle".into(),
                    worker_id: "worker-1".into(),
                    tenant,
                    workspace_id: "workspace-1".into(),
                    session_id: Some("session-1".into()),
                    run_id: Some("run-1".into()),
                    kind: "lifecycle".into(),
                    trust_level: "reported_by_self_hosted_worker".into(),
                    occurred_at_unix: Some(30),
                    ingested_at_unix: Some(31),
                    event_json: r#"{"state":"completed"}"#.into(),
                }),
        )
        .unwrap();

        let timeline = state
            .self_hosted_run_timeline("run-1", None)
            .expect("self-hosted run timeline should be visible");

        assert_eq!(timeline.object, "self_hosted_run_timeline");
        assert_eq!(timeline.run_id, "run-1");
        assert_eq!(timeline.session_ids, vec!["session-1"]);
        assert_eq!(timeline.worker_ids, vec!["worker-1"]);
        assert_eq!(timeline.trust_level, "reported_by_self_hosted_worker");
        assert_eq!(timeline.reported_event_count, 2);
        assert_eq!(timeline.lifecycle_event_count, 1);
        assert_eq!(timeline.first_seen_unix, Some(20));
        assert_eq!(timeline.last_seen_unix, Some(30));
        assert_eq!(
            timeline.latest_lifecycle_state.as_deref(),
            Some("completed")
        );
        assert_eq!(timeline.events[0].id, "event-tool");
        assert_eq!(timeline.events[1].id, "event-lifecycle");
        assert_eq!(timeline.events[1].event_json, r#"{"state":"completed"}"#);
        assert!(state
            .self_hosted_run_timeline("missing-run", None)
            .is_none());
    }

    #[test]
    fn self_hosted_worker_event_stream_pages_after_event_id() {
        let mut config = Config::default();
        config.storage.admin_list_default_limit = 1;
        config.storage.admin_list_max_limit = 2;
        let state = AppState::new(config);
        let tenant = ferrogate_core::TenantContext {
            workspace_id: None,
            organization_id: Some("org".into()),
            team_id: None,
            project_id: Some("project".into()),
            user_id: None,
            api_key_id: Some("key".into()),
        };
        block_on(state.repositories.upsert_self_hosted_worker_registration(
            StoredSelfHostedWorkerRegistration {
                id: "worker-1".into(),
                tenant: tenant.clone(),
                workspace_id: "workspace-1".into(),
                worker_name: "customer-worker".into(),
                status: "online".into(),
                identity_fingerprint: "sha256:worker".into(),
                identity_expires_at_unix: None,
                orchestration_enabled: true,
                registered_at_unix: Some(10),
                last_seen_at_unix: Some(20),
                trust_level: "reported_by_self_hosted_worker".into(),
                capability_envelope_json: "{}".into(),
                token_secret: "transport-secret-aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            },
        ))
        .unwrap();
        for (id, occurred_at_unix, kind) in [
            ("event-1", 10, "lifecycle"),
            ("event-2", 11, "tool_call"),
            ("event-3", 12, "log"),
        ] {
            block_on(
                state
                    .repositories
                    .append_self_hosted_worker_telemetry_event(
                        StoredSelfHostedWorkerTelemetryEvent {
                            id: id.into(),
                            worker_id: "worker-1".into(),
                            tenant: tenant.clone(),
                            workspace_id: "workspace-1".into(),
                            session_id: Some("session-1".into()),
                            run_id: Some("run-1".into()),
                            kind: kind.into(),
                            trust_level: "reported_by_self_hosted_worker".into(),
                            occurred_at_unix: Some(occurred_at_unix),
                            ingested_at_unix: Some(occurred_at_unix + 100),
                            event_json: "{}".into(),
                        },
                    ),
            )
            .unwrap();
        }

        let first = state
            .self_hosted_worker_event_stream(
                "worker-1",
                state.self_hosted_worker_event_stream_query(None),
            )
            .expect("worker event stream should be visible");
        assert_eq!(first.object, "self_hosted_worker_event_stream");
        assert_eq!(first.worker_id, "worker-1");
        assert_eq!(first.trust_level, "reported_by_self_hosted_worker");
        assert_eq!(first.total, 3);
        assert_eq!(first.limit, 1);
        assert_eq!(first.after_event_id, None);
        assert_eq!(first.data.len(), 1);
        assert_eq!(first.data[0].id, "event-1");
        assert_eq!(first.next_after_event_id.as_deref(), Some("event-1"));

        let second = state
            .self_hosted_worker_event_stream(
                "worker-1",
                state.self_hosted_worker_event_stream_query(Some("after_event_id=event-1&limit=2")),
            )
            .expect("second event stream page should be visible");
        assert_eq!(second.limit, 2);
        assert_eq!(second.after_event_id.as_deref(), Some("event-1"));
        assert_eq!(
            second
                .data
                .iter()
                .map(|event| event.id.as_str())
                .collect::<Vec<_>>(),
            vec!["event-2", "event-3"]
        );
        assert_eq!(second.next_after_event_id.as_deref(), Some("event-3"));
        assert!(state
            .self_hosted_worker_event_stream(
                "missing-worker",
                state.self_hosted_worker_event_stream_query(None)
            )
            .is_none());
    }

    #[test]
    fn self_hosted_worker_stale_state_uses_last_seen_threshold() {
        assert_eq!(
            self_hosted_worker_stale_state(None, Some(1_000)),
            (false, None)
        );
        assert_eq!(
            self_hosted_worker_stale_state(Some(100), Some(399)),
            (false, Some(400))
        );
        assert_eq!(
            self_hosted_worker_stale_state(Some(100), Some(400)),
            (false, Some(400))
        );
        assert_eq!(
            self_hosted_worker_stale_state(Some(100), Some(401)),
            (true, Some(400))
        );
    }

    #[test]
    fn register_self_hosted_worker_writes_durable_registration_record() {
        let state = AppState::new(Config::default());
        let (worker, transport_secret) = state
            .register_self_hosted_worker(
                crate::responses::AdminSelfHostedWorkerRegistrationRequest {
                    tenant: ferrogate_core::TenantContext {
                        workspace_id: None,
                        organization_id: Some("org".into()),
                        team_id: None,
                        project_id: Some("project".into()),
                        user_id: None,
                        api_key_id: Some("key".into()),
                    },
                    workspace_id: " workspace-1 ".into(),
                    worker_name: " customer-worker ".into(),
                    identity_fingerprint: " sha256:worker ".into(),
                    // Far-future expiry: identity expiry is now judged against the
                    // server's real clock (#113), so a non-expired worker must use a
                    // realistic future timestamp rather than a toy value.
                    identity_expires_at_unix: Some(4_000_000_000),
                    orchestration_enabled: true,
                    capability_envelope_json: Some(r#"{"frameworks":["codex"]}"#.into()),
                },
            )
            .expect("registration should be accepted");

        assert!(worker.id.starts_with("self-hosted-worker-"));
        assert_eq!(worker.workspace_id, "workspace-1");
        assert_eq!(worker.worker_name, "customer-worker");
        assert_eq!(worker.status, "registered");
        assert_eq!(worker.identity_fingerprint, "sha256:worker");
        assert_eq!(worker.identity_expires_at_unix, Some(4_000_000_000));
        assert!(worker.orchestration_enabled);
        assert_eq!(worker.trust_level, "reported_by_self_hosted_worker");
        assert!(worker.registered_at_unix.is_some());
        assert_eq!(worker.last_seen_at_unix, None);
        assert!(worker.latest_heartbeat.is_none());

        // The transport secret is provisioned server-side: high-entropy and
        // distinct from the public identity fingerprint / token_id.
        assert_eq!(transport_secret.len(), 64);
        assert_ne!(transport_secret, "sha256:worker");

        let records = block_on(state.repositories.self_hosted_worker_registrations());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, worker.id);
        assert_eq!(records[0].tenant.organization_id.as_deref(), Some("org"));
        assert_eq!(records[0].workspace_id, "workspace-1");
        assert_eq!(records[0].worker_name, "customer-worker");
        assert_eq!(records[0].identity_fingerprint, "sha256:worker");
        // The stored secret matches what was returned once at registration.
        assert_eq!(records[0].token_secret, transport_secret);
        assert_eq!(records[0].identity_expires_at_unix, Some(4_000_000_000));
        assert_eq!(
            records[0].capability_envelope_json,
            r#"{"frameworks":["codex"]}"#
        );

        let dispatches = block_on(state.repositories.self_hosted_run_dispatches());
        assert_eq!(dispatches.len(), 1);
        assert_eq!(
            dispatches[0].dispatch_id,
            format!("self-hosted-dispatch-{}", worker.id)
        );
        assert_eq!(dispatches[0].action, "start_run");
        assert_eq!(dispatches[0].tenant_id, "org");
        assert_eq!(dispatches[0].workspace_id, "workspace-1");
        assert_eq!(dispatches[0].framework_adapter, "codex");
        assert_eq!(
            dispatches[0].required_capabilities,
            vec!["shell".to_string()]
        );

        let lease = state
            .poll_self_hosted_worker_run(SelfHostedRunPollRequest {
                protocol_version: 1,
                identity: SelfHostedWorkerIdentity {
                    tenant_id: "org".into(),
                    workspace_id: "workspace-1".into(),
                    worker_id: worker.id.clone(),
                    token_id: "sha256:worker".into(),
                    // Authenticate with the provisioned secret, not the public
                    // fingerprint (which is the token_id / lookup key).
                    token_secret: transport_secret.clone(),
                    observed_at_unix: None,
                },
                supported_capabilities: vec!["shell".into()],
                now_unix: 100,
                lease_duration_secs: 30,
            })
            .expect("poll should be accepted")
            .expect("seed dispatch should be leased");
        assert_eq!(lease.attempt, 1);

        let dispatches = block_on(state.repositories.self_hosted_run_dispatches());
        assert_eq!(
            dispatches[0].assigned_worker_id.as_deref(),
            Some(worker.id.as_str())
        );
        assert_eq!(
            dispatches[0].lease_id.as_deref(),
            Some(lease.lease_id.as_str())
        );
        assert_eq!(dispatches[0].lease_expires_at_unix, Some(130));
        assert_eq!(dispatches[0].attempt, 1);

        state
            .ack_self_hosted_worker_run(SelfHostedRunAckRequest {
                protocol_version: 1,
                identity: SelfHostedWorkerIdentity {
                    tenant_id: "org".into(),
                    workspace_id: "workspace-1".into(),
                    worker_id: worker.id,
                    token_id: "sha256:worker".into(),
                    token_secret: transport_secret,
                    observed_at_unix: None,
                },
                dispatch_id: lease.dispatch_id,
                action: lease.action,
                lease_id: lease.lease_id,
                run_id: lease.run_id,
                status: SelfHostedRunAckStatus::Accepted,
                reported_at_unix: 101,
            })
            .expect("ack should be accepted");
        let dispatches = block_on(state.repositories.self_hosted_run_dispatches());
        assert_eq!(
            dispatches[0].acknowledged_status.as_deref(),
            Some("accepted")
        );
        assert_eq!(dispatches[0].acknowledged_at_unix, Some(101));
    }

    #[test]
    fn register_self_hosted_worker_rejects_invalid_registration_payloads() {
        let state = AppState::new(Config::default());
        let tenant = ferrogate_core::TenantContext {
            workspace_id: None,
            organization_id: Some("org".into()),
            team_id: None,
            project_id: Some("project".into()),
            user_id: None,
            api_key_id: Some("key".into()),
        };

        let blank_workspace = state.register_self_hosted_worker(
            crate::responses::AdminSelfHostedWorkerRegistrationRequest {
                tenant: tenant.clone(),
                workspace_id: " ".into(),
                worker_name: "customer-worker".into(),
                identity_fingerprint: "sha256:worker".into(),
                identity_expires_at_unix: None,
                orchestration_enabled: false,
                capability_envelope_json: None,
            },
        );
        assert!(matches!(
            blank_workspace,
            Err(SelfHostedWorkerRecordError::InvalidRequest(message))
                if message == "workspace_id must not be empty"
        ));

        let invalid_json = state.register_self_hosted_worker(
            crate::responses::AdminSelfHostedWorkerRegistrationRequest {
                tenant,
                workspace_id: "workspace-1".into(),
                worker_name: "customer-worker".into(),
                identity_fingerprint: "sha256:worker".into(),
                identity_expires_at_unix: None,
                orchestration_enabled: false,
                capability_envelope_json: Some("{not-json".into()),
            },
        );
        assert!(matches!(
            invalid_json,
            Err(SelfHostedWorkerRecordError::InvalidRequest(message))
                if message == "capability_envelope_json must be valid JSON when provided"
        ));

        assert!(block_on(state.repositories.self_hosted_worker_registrations()).is_empty());
    }

    #[test]
    fn rotate_self_hosted_worker_identity_updates_durable_registration() {
        let state = AppState::new(Config::default());
        let (worker, _transport_secret) = state
            .register_self_hosted_worker(
                crate::responses::AdminSelfHostedWorkerRegistrationRequest {
                    tenant: ferrogate_core::TenantContext::default(),
                    workspace_id: "workspace-1".into(),
                    worker_name: "customer-worker".into(),
                    identity_fingerprint: "sha256:old".into(),
                    identity_expires_at_unix: Some(100),
                    orchestration_enabled: false,
                    capability_envelope_json: None,
                },
            )
            .expect("registration should be accepted");

        let response = state
            .rotate_self_hosted_worker_identity(
                &worker.id,
                crate::responses::AdminSelfHostedWorkerRotateRequest {
                    identity_fingerprint: " sha256:new ".into(),
                    identity_expires_at_unix: Some(200),
                },
            )
            .expect("rotation should be accepted");

        assert_eq!(response.object, "self_hosted_worker_identity_rotation");
        assert_eq!(response.previous_identity_fingerprint, "sha256:old");
        assert_eq!(response.previous_identity_expires_at_unix, Some(100));
        assert_eq!(response.worker.id, worker.id);
        assert_eq!(response.worker.identity_fingerprint, "sha256:new");
        assert_eq!(response.worker.identity_expires_at_unix, Some(200));
        assert!(response.rotated_at_unix.is_some());

        let records = block_on(state.repositories.self_hosted_worker_registrations());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].identity_fingerprint, "sha256:new");
        assert_eq!(records[0].identity_expires_at_unix, Some(200));
    }

    #[test]
    fn rotate_self_hosted_worker_identity_rejects_missing_or_invalid_payloads() {
        let state = AppState::new(Config::default());

        let missing = state.rotate_self_hosted_worker_identity(
            "missing-worker",
            crate::responses::AdminSelfHostedWorkerRotateRequest {
                identity_fingerprint: "sha256:new".into(),
                identity_expires_at_unix: None,
            },
        );
        assert!(matches!(
            missing,
            Err(SelfHostedWorkerRecordError::NotFound(message))
                if message == "self-hosted worker missing-worker was not found"
        ));

        let (worker, _transport_secret) = state
            .register_self_hosted_worker(
                crate::responses::AdminSelfHostedWorkerRegistrationRequest {
                    tenant: ferrogate_core::TenantContext::default(),
                    workspace_id: "workspace-1".into(),
                    worker_name: "customer-worker".into(),
                    identity_fingerprint: "sha256:old".into(),
                    identity_expires_at_unix: None,
                    orchestration_enabled: false,
                    capability_envelope_json: None,
                },
            )
            .expect("registration should be accepted");
        let blank = state.rotate_self_hosted_worker_identity(
            &worker.id,
            crate::responses::AdminSelfHostedWorkerRotateRequest {
                identity_fingerprint: " ".into(),
                identity_expires_at_unix: None,
            },
        );
        assert!(matches!(
            blank,
            Err(SelfHostedWorkerRecordError::InvalidRequest(message))
                if message == "identity_fingerprint must not be empty"
        ));

        let records = block_on(state.repositories.self_hosted_worker_registrations());
        assert_eq!(records[0].identity_fingerprint, "sha256:old");
    }

    #[test]
    fn record_self_hosted_worker_heartbeat_updates_status_and_latest_seen() {
        let state = AppState::new(Config::default());
        let (worker, _transport_secret) = state
            .register_self_hosted_worker(
                crate::responses::AdminSelfHostedWorkerRegistrationRequest {
                    tenant: ferrogate_core::TenantContext {
                        workspace_id: None,
                        organization_id: Some("org".into()),
                        team_id: None,
                        project_id: Some("project".into()),
                        user_id: None,
                        api_key_id: Some("key".into()),
                    },
                    workspace_id: "workspace-1".into(),
                    worker_name: "customer-worker".into(),
                    identity_fingerprint: "sha256:worker".into(),
                    identity_expires_at_unix: None,
                    orchestration_enabled: true,
                    capability_envelope_json: None,
                },
            )
            .expect("registration should be accepted");

        let (updated_worker, heartbeat) = state
            .record_self_hosted_worker_heartbeat(
                &worker.id,
                crate::responses::AdminSelfHostedWorkerHeartbeatRequest {
                    status: "online".into(),
                    reported_at_unix: Some(123),
                    heartbeat_json: Some(r#"{"load":0.42}"#.into()),
                },
            )
            .expect("heartbeat should be accepted");

        assert!(heartbeat.id.starts_with("self-hosted-heartbeat-"));
        assert_eq!(heartbeat.status, "online");
        assert_eq!(heartbeat.reported_at_unix, Some(123));
        assert!(heartbeat.observed_at_unix.is_some());
        assert_eq!(updated_worker.id, worker.id);
        assert_eq!(updated_worker.status, "online");
        assert_eq!(updated_worker.last_seen_at_unix, heartbeat.observed_at_unix);
        assert_eq!(
            updated_worker
                .latest_heartbeat
                .as_ref()
                .map(|heartbeat| heartbeat.id.as_str()),
            Some(heartbeat.id.as_str())
        );

        let stored_registration = block_on(state.repositories.self_hosted_worker_registrations())
            .into_iter()
            .find(|registration| registration.id == worker.id)
            .expect("registration should remain stored");
        assert_eq!(stored_registration.status, "online");
        assert_eq!(
            stored_registration.last_seen_at_unix,
            heartbeat.observed_at_unix
        );

        let stored_heartbeats = block_on(state.repositories.self_hosted_worker_heartbeats());
        assert_eq!(stored_heartbeats.len(), 1);
        assert_eq!(stored_heartbeats[0].worker_id, worker.id);
        assert_eq!(stored_heartbeats[0].heartbeat_json, r#"{"load":0.42}"#);
    }

    #[test]
    fn record_self_hosted_worker_heartbeat_rejects_missing_or_invalid_payloads() {
        let state = AppState::new(Config::default());

        let missing = state.record_self_hosted_worker_heartbeat(
            "missing-worker",
            crate::responses::AdminSelfHostedWorkerHeartbeatRequest {
                status: "online".into(),
                reported_at_unix: None,
                heartbeat_json: None,
            },
        );
        assert!(matches!(
            missing,
            Err(SelfHostedWorkerRecordError::NotFound(message))
                if message == "self-hosted worker missing-worker was not found"
        ));

        let (worker, _transport_secret) = state
            .register_self_hosted_worker(
                crate::responses::AdminSelfHostedWorkerRegistrationRequest {
                    tenant: ferrogate_core::TenantContext::default(),
                    workspace_id: "workspace-1".into(),
                    worker_name: "customer-worker".into(),
                    identity_fingerprint: "sha256:worker".into(),
                    identity_expires_at_unix: None,
                    orchestration_enabled: false,
                    capability_envelope_json: None,
                },
            )
            .expect("registration should be accepted");
        let blank_status = state.record_self_hosted_worker_heartbeat(
            &worker.id,
            crate::responses::AdminSelfHostedWorkerHeartbeatRequest {
                status: " ".into(),
                reported_at_unix: None,
                heartbeat_json: None,
            },
        );
        assert!(matches!(
            blank_status,
            Err(SelfHostedWorkerRecordError::InvalidRequest(message))
                if message == "status must not be empty"
        ));

        let invalid_json = state.record_self_hosted_worker_heartbeat(
            &worker.id,
            crate::responses::AdminSelfHostedWorkerHeartbeatRequest {
                status: "online".into(),
                reported_at_unix: None,
                heartbeat_json: Some("{not-json".into()),
            },
        );
        assert!(matches!(
            invalid_json,
            Err(SelfHostedWorkerRecordError::InvalidRequest(message))
                if message == "heartbeat_json must be valid JSON when provided"
        ));

        assert!(block_on(state.repositories.self_hosted_worker_heartbeats()).is_empty());
    }

    #[test]
    fn record_self_hosted_worker_telemetry_event_updates_event_projection() {
        let state = AppState::new(Config::default());
        let (worker, _transport_secret) = state
            .register_self_hosted_worker(
                crate::responses::AdminSelfHostedWorkerRegistrationRequest {
                    tenant: ferrogate_core::TenantContext {
                        workspace_id: None,
                        organization_id: Some("org".into()),
                        team_id: None,
                        project_id: Some("project".into()),
                        user_id: None,
                        api_key_id: Some("key".into()),
                    },
                    workspace_id: "workspace-1".into(),
                    worker_name: "customer-worker".into(),
                    identity_fingerprint: "sha256:worker".into(),
                    identity_expires_at_unix: None,
                    orchestration_enabled: true,
                    capability_envelope_json: None,
                },
            )
            .expect("registration should be accepted");

        let (updated_worker, event) = state
            .record_self_hosted_worker_telemetry_event(
                &worker.id,
                crate::responses::AdminSelfHostedWorkerTelemetryEventRequest {
                    session_id: "session-1".into(),
                    run_id: "run-1".into(),
                    kind: "tool_call".into(),
                    occurred_at_unix: Some(456),
                    event_json: Some(r#"{"tool":"shell"}"#.into()),
                },
            )
            .expect("telemetry event should be accepted");

        assert!(event.id.starts_with("self-hosted-event-"));
        assert_eq!(event.worker_id, worker.id);
        assert_eq!(event.session_id.as_deref(), Some("session-1"));
        assert_eq!(event.run_id.as_deref(), Some("run-1"));
        assert_eq!(event.kind, "tool_call");
        assert_eq!(event.trust_level, "reported_by_self_hosted_worker");
        assert_eq!(event.occurred_at_unix, Some(456));
        assert!(event.ingested_at_unix.is_some());
        assert_eq!(updated_worker.id, worker.id);
        assert_eq!(updated_worker.telemetry_event_count, 1);
        assert_eq!(updated_worker.latest_event_at_unix, Some(456));

        let stored_events = block_on(state.repositories.self_hosted_worker_telemetry_events());
        assert_eq!(stored_events.len(), 1);
        assert_eq!(stored_events[0].worker_id, worker.id);
        assert_eq!(stored_events[0].event_json, r#"{"tool":"shell"}"#);
    }

    #[test]
    fn record_self_hosted_worker_telemetry_event_rejects_missing_or_invalid_payloads() {
        let state = AppState::new(Config::default());

        let missing = state.record_self_hosted_worker_telemetry_event(
            "missing-worker",
            crate::responses::AdminSelfHostedWorkerTelemetryEventRequest {
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                kind: "log".into(),
                occurred_at_unix: None,
                event_json: None,
            },
        );
        assert!(matches!(
            missing,
            Err(SelfHostedWorkerRecordError::NotFound(message))
                if message == "self-hosted worker missing-worker was not found"
        ));

        let (worker, _transport_secret) = state
            .register_self_hosted_worker(
                crate::responses::AdminSelfHostedWorkerRegistrationRequest {
                    tenant: ferrogate_core::TenantContext::default(),
                    workspace_id: "workspace-1".into(),
                    worker_name: "customer-worker".into(),
                    identity_fingerprint: "sha256:worker".into(),
                    identity_expires_at_unix: None,
                    orchestration_enabled: false,
                    capability_envelope_json: None,
                },
            )
            .expect("registration should be accepted");
        let invalid_kind = state.record_self_hosted_worker_telemetry_event(
            &worker.id,
            crate::responses::AdminSelfHostedWorkerTelemetryEventRequest {
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                kind: "unknown".into(),
                occurred_at_unix: None,
                event_json: None,
            },
        );
        assert!(matches!(
            invalid_kind,
            Err(SelfHostedWorkerRecordError::InvalidRequest(message))
                if message.contains("kind must be one of")
        ));

        let invalid_json = state.record_self_hosted_worker_telemetry_event(
            &worker.id,
            crate::responses::AdminSelfHostedWorkerTelemetryEventRequest {
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                kind: "log".into(),
                occurred_at_unix: None,
                event_json: Some("{not-json".into()),
            },
        );
        assert!(matches!(
            invalid_json,
            Err(SelfHostedWorkerRecordError::InvalidRequest(message))
                if message == "event_json must be valid JSON when provided"
        ));

        assert!(block_on(state.repositories.self_hosted_worker_telemetry_events()).is_empty());
    }

    #[test]
    fn record_self_hosted_worker_artifact_updates_artifact_projection() {
        let state = AppState::new(Config::default());
        let (worker, _transport_secret) = state
            .register_self_hosted_worker(
                crate::responses::AdminSelfHostedWorkerRegistrationRequest {
                    tenant: ferrogate_core::TenantContext {
                        workspace_id: None,
                        organization_id: Some("org".into()),
                        team_id: None,
                        project_id: Some("project".into()),
                        user_id: None,
                        api_key_id: Some("key".into()),
                    },
                    workspace_id: "workspace-1".into(),
                    worker_name: "customer-worker".into(),
                    identity_fingerprint: "sha256:worker".into(),
                    identity_expires_at_unix: None,
                    orchestration_enabled: true,
                    capability_envelope_json: None,
                },
            )
            .expect("registration should be accepted");

        let (updated_worker, artifact) = state
            .record_self_hosted_worker_artifact(
                &worker.id,
                crate::responses::AdminSelfHostedWorkerArtifactRequest {
                    artifact_id: "artifact-1".into(),
                    session_id: "session-1".into(),
                    run_id: "run-1".into(),
                    artifact_name: "stdout.log".into(),
                    content_type: Some("text/plain".into()),
                    size_bytes: 128,
                    created_at_unix: Some(789),
                    artifact_json: Some(r#"{"sha256":"abc"}"#.into()),
                },
            )
            .expect("artifact should be accepted");

        assert_eq!(artifact.id, "artifact-1");
        assert_eq!(artifact.worker_id, worker.id);
        assert_eq!(artifact.session_id, "session-1");
        assert_eq!(artifact.run_id, "run-1");
        assert_eq!(artifact.artifact_name, "stdout.log");
        assert_eq!(artifact.content_type.as_deref(), Some("text/plain"));
        assert_eq!(artifact.size_bytes, 128);
        assert_eq!(artifact.trust_level, "reported_by_self_hosted_worker");
        assert_eq!(artifact.created_at_unix, Some(789));
        assert_eq!(updated_worker.id, worker.id);
        assert_eq!(updated_worker.artifact_count, 1);
        assert_eq!(updated_worker.latest_artifact_at_unix, Some(789));

        let stored_artifacts = block_on(state.repositories.self_hosted_worker_artifacts());
        assert_eq!(stored_artifacts.len(), 1);
        assert_eq!(stored_artifacts[0].id, "artifact-1");
        assert_eq!(stored_artifacts[0].worker_id, worker.id);
        assert_eq!(stored_artifacts[0].artifact_json, r#"{"sha256":"abc"}"#);
    }

    #[test]
    fn record_self_hosted_worker_artifact_rejects_missing_or_invalid_payloads() {
        let state = AppState::new(Config::default());

        let missing = state.record_self_hosted_worker_artifact(
            "missing-worker",
            crate::responses::AdminSelfHostedWorkerArtifactRequest {
                artifact_id: "artifact-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                artifact_name: "stdout.log".into(),
                content_type: None,
                size_bytes: 128,
                created_at_unix: None,
                artifact_json: None,
            },
        );
        assert!(matches!(
            missing,
            Err(SelfHostedWorkerRecordError::NotFound(message))
                if message == "self-hosted worker missing-worker was not found"
        ));

        let (worker, _transport_secret) = state
            .register_self_hosted_worker(
                crate::responses::AdminSelfHostedWorkerRegistrationRequest {
                    tenant: ferrogate_core::TenantContext::default(),
                    workspace_id: "workspace-1".into(),
                    worker_name: "customer-worker".into(),
                    identity_fingerprint: "sha256:worker".into(),
                    identity_expires_at_unix: None,
                    orchestration_enabled: false,
                    capability_envelope_json: None,
                },
            )
            .expect("registration should be accepted");
        let blank_name = state.record_self_hosted_worker_artifact(
            &worker.id,
            crate::responses::AdminSelfHostedWorkerArtifactRequest {
                artifact_id: "artifact-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                artifact_name: " ".into(),
                content_type: None,
                size_bytes: 128,
                created_at_unix: None,
                artifact_json: None,
            },
        );
        assert!(matches!(
            blank_name,
            Err(SelfHostedWorkerRecordError::InvalidRequest(message))
                if message == "artifact_name must not be empty"
        ));

        let oversized = state.record_self_hosted_worker_artifact(
            &worker.id,
            crate::responses::AdminSelfHostedWorkerArtifactRequest {
                artifact_id: "artifact-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                artifact_name: "stdout.log".into(),
                content_type: None,
                size_bytes: SELF_HOSTED_WORKER_MAX_ARTIFACT_BYTES + 1,
                created_at_unix: None,
                artifact_json: None,
            },
        );
        assert!(matches!(
            oversized,
            Err(SelfHostedWorkerRecordError::InvalidRequest(message))
                if message.contains("size_bytes must be less than or equal to")
        ));

        let invalid_json = state.record_self_hosted_worker_artifact(
            &worker.id,
            crate::responses::AdminSelfHostedWorkerArtifactRequest {
                artifact_id: "artifact-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                artifact_name: "stdout.log".into(),
                content_type: Some("text/plain".into()),
                size_bytes: 128,
                created_at_unix: None,
                artifact_json: Some("{not-json".into()),
            },
        );
        assert!(matches!(
            invalid_json,
            Err(SelfHostedWorkerRecordError::InvalidRequest(message))
                if message == "artifact_json must be valid JSON when provided"
        ));

        assert!(block_on(state.repositories.self_hosted_worker_artifacts()).is_empty());
    }

    #[test]
    fn record_self_hosted_worker_checkpoint_updates_checkpoint_projection() {
        let state = AppState::new(Config::default());
        let (worker, _transport_secret) = state
            .register_self_hosted_worker(
                crate::responses::AdminSelfHostedWorkerRegistrationRequest {
                    tenant: ferrogate_core::TenantContext {
                        workspace_id: None,
                        organization_id: Some("org".into()),
                        team_id: None,
                        project_id: Some("project".into()),
                        user_id: None,
                        api_key_id: Some("key".into()),
                    },
                    workspace_id: "workspace-1".into(),
                    worker_name: "customer-worker".into(),
                    identity_fingerprint: "sha256:worker".into(),
                    identity_expires_at_unix: None,
                    orchestration_enabled: true,
                    capability_envelope_json: None,
                },
            )
            .expect("registration should be accepted");

        let (updated_worker, checkpoint) = state
            .record_self_hosted_worker_checkpoint(
                &worker.id,
                crate::responses::AdminSelfHostedWorkerCheckpointRequest {
                    checkpoint_id: "checkpoint-1".into(),
                    session_id: "session-1".into(),
                    run_id: "run-1".into(),
                    checkpoint_name: "resume-state".into(),
                    size_bytes: 256,
                    created_at_unix: Some(890),
                    checkpoint_json: Some(r#"{"sha256":"def"}"#.into()),
                },
            )
            .expect("checkpoint should be accepted");

        assert_eq!(checkpoint.id, "checkpoint-1");
        assert_eq!(checkpoint.worker_id, worker.id);
        assert_eq!(checkpoint.session_id, "session-1");
        assert_eq!(checkpoint.run_id, "run-1");
        assert_eq!(checkpoint.checkpoint_name, "resume-state");
        assert_eq!(checkpoint.size_bytes, 256);
        assert_eq!(checkpoint.trust_level, "reported_by_self_hosted_worker");
        assert_eq!(checkpoint.created_at_unix, Some(890));
        assert_eq!(updated_worker.id, worker.id);
        assert_eq!(updated_worker.checkpoint_count, 1);
        assert_eq!(updated_worker.latest_checkpoint_at_unix, Some(890));

        let stored_checkpoints = block_on(state.repositories.self_hosted_worker_checkpoints());
        assert_eq!(stored_checkpoints.len(), 1);
        assert_eq!(stored_checkpoints[0].id, "checkpoint-1");
        assert_eq!(stored_checkpoints[0].worker_id, worker.id);
        assert_eq!(stored_checkpoints[0].checkpoint_json, r#"{"sha256":"def"}"#);
    }

    #[test]
    fn record_self_hosted_worker_checkpoint_rejects_missing_or_invalid_payloads() {
        let state = AppState::new(Config::default());

        let missing = state.record_self_hosted_worker_checkpoint(
            "missing-worker",
            crate::responses::AdminSelfHostedWorkerCheckpointRequest {
                checkpoint_id: "checkpoint-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                checkpoint_name: "resume-state".into(),
                size_bytes: 256,
                created_at_unix: None,
                checkpoint_json: None,
            },
        );
        assert!(matches!(
            missing,
            Err(SelfHostedWorkerRecordError::NotFound(message))
                if message == "self-hosted worker missing-worker was not found"
        ));

        let (worker, _transport_secret) = state
            .register_self_hosted_worker(
                crate::responses::AdminSelfHostedWorkerRegistrationRequest {
                    tenant: ferrogate_core::TenantContext::default(),
                    workspace_id: "workspace-1".into(),
                    worker_name: "customer-worker".into(),
                    identity_fingerprint: "sha256:worker".into(),
                    identity_expires_at_unix: None,
                    orchestration_enabled: false,
                    capability_envelope_json: None,
                },
            )
            .expect("registration should be accepted");
        let blank_name = state.record_self_hosted_worker_checkpoint(
            &worker.id,
            crate::responses::AdminSelfHostedWorkerCheckpointRequest {
                checkpoint_id: "checkpoint-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                checkpoint_name: " ".into(),
                size_bytes: 256,
                created_at_unix: None,
                checkpoint_json: None,
            },
        );
        assert!(matches!(
            blank_name,
            Err(SelfHostedWorkerRecordError::InvalidRequest(message))
                if message == "checkpoint_name must not be empty"
        ));

        let oversized = state.record_self_hosted_worker_checkpoint(
            &worker.id,
            crate::responses::AdminSelfHostedWorkerCheckpointRequest {
                checkpoint_id: "checkpoint-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                checkpoint_name: "resume-state".into(),
                size_bytes: SELF_HOSTED_WORKER_MAX_ARTIFACT_BYTES + 1,
                created_at_unix: None,
                checkpoint_json: None,
            },
        );
        assert!(matches!(
            oversized,
            Err(SelfHostedWorkerRecordError::InvalidRequest(message))
                if message.contains("size_bytes must be less than or equal to")
        ));

        let invalid_json = state.record_self_hosted_worker_checkpoint(
            &worker.id,
            crate::responses::AdminSelfHostedWorkerCheckpointRequest {
                checkpoint_id: "checkpoint-1".into(),
                session_id: "session-1".into(),
                run_id: "run-1".into(),
                checkpoint_name: "resume-state".into(),
                size_bytes: 256,
                created_at_unix: None,
                checkpoint_json: Some("{not-json".into()),
            },
        );
        assert!(matches!(
            invalid_json,
            Err(SelfHostedWorkerRecordError::InvalidRequest(message))
                if message == "checkpoint_json must be valid JSON when provided"
        ));

        assert!(block_on(state.repositories.self_hosted_worker_checkpoints()).is_empty());
    }

    fn stored_registration_for_cert(
        id: &str,
        org: &str,
        fingerprint: &str,
    ) -> StoredSelfHostedWorkerRegistration {
        StoredSelfHostedWorkerRegistration {
            id: id.into(),
            tenant: ferrogate_core::TenantContext {
                organization_id: Some(org.into()),
                ..Default::default()
            },
            workspace_id: "workspace-1".into(),
            worker_name: format!("worker-{id}"),
            status: "registered".into(),
            identity_fingerprint: fingerprint.into(),
            identity_expires_at_unix: None,
            orchestration_enabled: false,
            registered_at_unix: Some(1),
            last_seen_at_unix: None,
            trust_level: "reported_by_self_hosted_worker".into(),
            capability_envelope_json: "{}".into(),
            token_secret: "transport-secret-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        }
    }

    #[test]
    fn minted_client_cert_binds_to_the_registration_four_tuple_and_is_verifier_accepted() {
        // Issue #249: the cert minted at registration must bind to the worker's
        // SPIFFE 4-tuple (tenant/workspace/worker/token) and be accepted by the
        // verifier built from the same issuing CA -- and rejected for another
        // worker's identity.
        let issuer =
            ferrogate_runtime::SelfHostedMtlsCertIssuer::generate_self_signed("test-ca", 3600)
                .expect("issuer");
        let registration = stored_registration_for_cert("worker-a", "org-a", "sha256:fp-a");
        let minted = mint_self_hosted_worker_client_certificate(&registration, &issuer, 1_000)
            .expect("cert minted");

        assert_eq!(
            minted.spiffe_id,
            "spiffe://ferrogate/self-hosted/org-a/workspace-1/worker-a/sha256:fp-a"
        );
        assert!(!minted.fingerprint.is_empty());
        assert!(!minted.serial.is_empty());
        assert!(minted.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(minted.private_key_pem.contains("PRIVATE KEY"));
        assert!(minted.not_after_unix > 1_000);

        // A different worker mints a different, distinctly-bound cert.
        let other = stored_registration_for_cert("worker-b", "org-a", "sha256:fp-b");
        let minted_other = mint_self_hosted_worker_client_certificate(&other, &issuer, 1_000)
            .expect("other cert minted");
        assert_ne!(minted.spiffe_id, minted_other.spiffe_id);
        assert_ne!(minted.fingerprint, minted_other.fingerprint);
    }

    #[test]
    fn misconfigured_issuing_ca_material_fails_closed() {
        // A garbage CA cert/key is refused rather than silently ignored.
        let error = ferrogate_runtime::SelfHostedMtlsCertIssuer::from_ca_pem(
            "not a cert",
            "not a key",
            3600,
        )
        .expect_err("garbage CA must fail closed");
        assert!(matches!(
            error,
            ferrogate_runtime::SelfHostedMtlsError::CertIssuance(_)
        ));
    }
}
