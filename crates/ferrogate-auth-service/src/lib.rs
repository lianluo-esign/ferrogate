// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Tenant and RBAC service boundaries.
//!
//! This crate owns the optional external auth/control-plane process. The
//! gateway should consume the REST API decision output, not embed role,
//! permission, or binding evaluation in the request hot path.
//!
//! # Why `-service` is in the name
//!
//! Until #553 stage 4 this crate was `ferrogate-auth`, one word away from
//! `ferrogate_gateway::auth` — the gateway's *request authenticator*, which
//! decides whether a presented credential may make a given call. The two are
//! different things: this crate is the identity SERVICE the gateway talks to
//! over HTTP (`AuthDecision`, `AuthorizationDecision`), and it also carries
//! SSO/SAML/SCIM and the admin-console session API, none of which the
//! authenticator knows about. The `-service` suffix makes the import line say
//! which one you mean.
//!
//! The name change stops at the crate: the binary is still `ferrogate-auth`
//! (`[[bin]]` in `Cargo.toml`) and `/health` still reports
//! `"service": "ferrogate-auth"`, because those are the deployment and wire
//! contracts, and stage 4 changes no behaviour.
//!
//! The crate entry file stays thin (docs/engineering-standards.md, issue
//! #433): each concern lives in a sibling module below and the full public
//! API is re-exported here unchanged.

mod admin_console;
mod api_key;
mod http;
mod membership_role;
mod rbac;
mod saml;
mod scim;
mod server;
mod sso;
mod util;

pub use admin_console::{
    AdminChangeRoleRequest, AdminConsoleConfig, AdminInviteRequest, AdminLoginRequest,
    AdminLogoutRequest, AdminMeResponse, AdminRefreshRequest, AdminRegisterRequest,
    AdminSessionResponse, AdminTeamMemberView, AdminTenantView, AdminUserView,
    BindingUpsertRequest, RoleUpsertRequest,
};
pub use api_key::{
    generate_virtual_api_key_secret, hash_virtual_api_key_secret, virtual_api_key_material,
    ApiKeyAuthenticator, StorageApiKeyAuthenticator, VirtualApiKeyMaterial,
};
pub use http::{read_http_request_bounded, HttpRequest, HttpResponse, RequestLengthError};
pub use membership_role::{InvalidMembershipRole, MembershipRole};
pub use rbac::{
    AuthApiKey, AuthDecision, AuthServiceData, AuthorizationDecision, AuthorizeRequest, Permission,
    PolicyBinding, PolicySubject, RbacAuthService, Role, TenantRecord,
};
pub use scim::AdminScimTokenResponse;
pub use server::{serve, serve_connections, AuthService, AuthServiceConfig, ResolveApiKeyRequest};
pub use sso::SsoConfigRequest;

// The `saml` module reaches shared helpers through `super::` paths; keep
// those names resolvable at the crate root.
pub(crate) use http::urldecode;
pub(crate) use sso::urlencode;
pub(crate) use util::is_valid_email;

// The sibling test files below are declared at the crate root (their
// pre-split home) and reach crate internals through `use super::*`; surface
// every module's items -- and the external names the tests pull from the
// root scope -- here, test builds only.
#[cfg(test)]
pub(crate) use {admin_console::*, http::*, scim::*, server::*, sso::*, util::*};

#[cfg(test)]
use base64::Engine as _;
#[cfg(test)]
use blake2::{Blake2b512, Digest};
#[cfg(test)]
use ferrogate_core::TenantContext;
#[cfg(test)]
use ferrogate_storage::{
    RuntimeStorageRepositories, StoredAdminUser, StoredAdminUserMembership,
    StoredAdminUserRefreshToken, StoredApiKey, StoredSsoPendingFlow,
};
#[cfg(test)]
use jsonwebtoken::{encode, Header};
#[cfg(test)]
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
    time::Duration,
};

#[cfg(test)]
#[path = "rbac_test.rs"]
mod rbac_test;

#[cfg(test)]
#[path = "hardening_test.rs"]
mod hardening_test;

#[cfg(test)]
#[path = "admin_console_test.rs"]
mod admin_console_test;

#[cfg(test)]
#[path = "credential_debug_test.rs"]
mod credential_debug_test;

#[cfg(test)]
#[path = "membership_role_test.rs"]
mod membership_role_test;
