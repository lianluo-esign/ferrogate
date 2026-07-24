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
//! The crate entry file stays thin (docs/engineering-standards.md, issue
//! #433): each concern lives in a sibling module below and the full public
//! API is re-exported here unchanged.

mod admin_console;
mod api_key;
mod http;
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
    RuntimeStorageRepositories, StoredAdminUserRefreshToken, StoredApiKey, StoredSsoPendingFlow,
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
