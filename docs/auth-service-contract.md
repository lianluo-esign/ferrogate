# External Auth Service Contract

FerroGate can keep tenant RBAC outside the gateway process by enabling an
external auth service. The built-in implementation is `ferrogate-auth`, but the
gateway only depends on the REST contract below, so a third-party service can
replace it.

## Gateway Configuration

```yaml
auth_service:
  enabled: true
  endpoint: "http://127.0.0.1:8090"
  timeout_millis: 1000
  max_retries: 2
  retry_backoff_millis: 50
```

When `auth_service.enabled` is `false`, FerroGate uses the existing local
`api_keys` configuration. When it is `true`, the gateway resolves presented API
keys through the external service and fails closed if the service is unavailable
or rejects the request.

The current gateway client supports `http://` endpoints and bounded retries for
transport and 5xx failures. It does not retry 401, 403, or denied RBAC
decisions. Put TLS termination, service discovery, and mTLS policy in front of
the service until the gateway grows those client-side controls explicitly.

## Health

`GET /healthz` and `GET /v1/healthz` return service readiness.

Response:

```json
{
  "service": "ferrogate-auth",
  "status": "ok"
}
```

## Resolve API Key

`POST /v1/auth/resolve-api-key` maps a presented secret to tenant context,
subject, and scopes.

Request:

```json
{
  "presented_key": "client-secret"
}
```

Success response:

```json
{
  "tenant": {
    "organization_id": "org_demo",
    "team_id": null,
    "project_id": "project_gateway",
    "user_id": null,
    "api_key_id": "client"
  },
  "subject": {
    "type": "api_key",
    "api_key_id": "client"
  },
  "scopes": ["models.read", "chat.completions"]
}
```

Unknown, disabled, or expired keys should return `401` or `403`. The gateway
does not fall back to local API keys after an external auth failure.

Scopes must explicitly include the required gateway scope or `*`. Empty scopes
are not treated as all-access for external auth.

## Authorize

`POST /v1/auth/authorize` evaluates tenant RBAC for an action and resource.

Request:

```json
{
  "tenant": {
    "organization_id": "org_demo",
    "team_id": null,
    "project_id": "project_gateway",
    "user_id": null,
    "api_key_id": "client"
  },
  "subject": {
    "type": "api_key",
    "api_key_id": "client"
  },
  "action": "chat.completions",
  "resource": "model:fast-chat"
}
```

Decision response:

```json
{
  "allowed": true,
  "tenant": {
    "organization_id": "org_demo",
    "team_id": null,
    "project_id": "project_gateway",
    "user_id": null,
    "api_key_id": "client"
  },
  "reason": "matched_rbac_binding"
}
```

For AI traffic, the gateway currently authorizes `model:<logical_model>` before
provider dispatch. A denied decision returns `403 rbac_denied` and the provider
is not called.

## Built-In Service Data

`ferrogate-auth serve --listen <addr> --data <path.yaml>` loads tenant, key,
role, and binding data from YAML:

```yaml
api_keys:
  - id: client
    secret: client-secret
    enabled: true
    tenant:
      organization_id: org_demo
      project_id: project_gateway
      api_key_id: client
    scopes:
      - models.read
      - chat.completions
roles:
  - id: role-chat-caller
    name: Chat caller
    permissions:
      - action: chat.completions
        resource: model:fast-chat
bindings:
  - id: binding-client-chat
    role_id: role-chat-caller
    tenant:
      organization_id: org_demo
      project_id: project_gateway
      api_key_id: client
    subject:
      type: api_key
      api_key_id: client
```

Third-party services do not need to use this schema internally. They only need
to implement the REST request and response contract.
