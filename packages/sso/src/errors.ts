/**
 * Every SAML refusal in this package is one of these two errors, and every one
 * of them carries the VERBATIM message string its Rust twin produced.
 *
 * Two error types, because the Rust port had two layers with different
 * responsibilities:
 *
 *  * `SamlError` — `crates/ferrogate-auth-service/src/saml.rs`, whose functions
 *    return `Result<_, String>`. The `message` field of each variant below is
 *    that exact string. `code` is this port's addition: the Rust strings are
 *    prose and are matched on with `.contains(...)` in the Rust suite, which is
 *    a fragile way to assert a security decision. Callers here match on `code`;
 *    `message` is kept only so the port is greppable against the Rust source.
 *
 *  * `SamlFlowError` — `sso.rs`'s handler layer, which returns an
 *    `HttpResponse` with a STATUS. The status is part of the contract (401 vs
 *    422 vs 500 vs 404), so it is carried explicitly rather than being decided
 *    by whoever mounts the routes.
 *
 * Neither type is ever constructed for a success path, and neither has a
 * "warn and continue" mode: `sso.rs`'s SAML handlers return early on each of
 * these, so this port throws.
 */

/** Refusal codes for the protocol layer (`saml.rs`). */
export type SamlErrorCode =
  // -- certificate / key (saml.rs::certificate_der, parse_idp_public_key)
  | "certificate_not_base64"
  | "invalid_x509_certificate"
  | "certificate_empty_public_key"
  // -- redirect-binding signature (saml.rs::verify_redirect_signature)
  | "response_not_signed"
  | "missing_sig_alg"
  | "unsupported_sig_alg"
  | "signature_not_base64"
  | "missing_saml_response"
  | "signature_verification_failed"
  // -- payload decoding (saml.rs::parse_response_xml)
  | "saml_response_not_base64"
  | "saml_response_inflate_failed"
  | "malformed_saml_xml"
  // -- NO RUST TWIN: a Workers-side resource bound, see response.ts
  | "saml_response_too_large"
  // -- assertion validation (saml.rs::parse_and_validate_response)
  | "status_not_success"
  | "in_response_to_mismatch"
  | "issuer_mismatch"
  | "audience_mismatch"
  | "assertion_not_yet_valid"
  | "assertion_expired"
  | "no_usable_email"
  // -- instant parsing (saml.rs::parse_saml_instant)
  | "saml_instant_not_utc"
  | "saml_instant_missing_time"
  | "saml_instant_missing_field"
  | "saml_instant_invalid_field"
  | "saml_instant_out_of_range";

/** A protocol-level refusal. Always fatal to the login attempt. */
export class SamlError extends Error {
  readonly code: SamlErrorCode;

  constructor(code: SamlErrorCode, message: string) {
    super(message);
    this.name = "SamlError";
    this.code = code;
  }
}

export function samlError(code: SamlErrorCode, message: string): SamlError {
  return new SamlError(code, message);
}

/**
 * Renders a value the way Rust's `{:?}` would for the `Option<String>` /
 * `&str` values that reach these messages, so the ported strings are
 * character-identical to the Rust ones.
 */
export function rustDebug(value: string | null | undefined): string {
  if (value === null || value === undefined) return "None";
  return `Some(${rustDebugStr(value)})`;
}

export function rustDebugStr(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** Refusal codes for the flow/handler layer (`sso.rs`). */
export type SamlFlowErrorCode =
  | "sso_not_configured"
  | "not_saml_tenant"
  | "saml_config_incomplete"
  | "missing_relay_state"
  | "missing_saml_response_param"
  | "unknown_saml_state"
  | "flow_not_saml"
  | "saml_config_removed_mid_flow"
  | "sso_config_no_longer_saml"
  | "saml_config_missing_certificate"
  | "saml_signature_verification_failed"
  | "saml_assertion_rejected"
  // -- config admission (sso.rs::handle_set_sso_config, "saml" branch)
  | "not_saml_config"
  | "saml_config_incomplete_fields"
  | "saml_certificate_unusable";

/** A handler-level refusal, carrying the HTTP status the Rust handler returned. */
export class SamlFlowError extends Error {
  readonly code: SamlFlowErrorCode;
  readonly status: number;

  constructor(code: SamlFlowErrorCode, status: number, message: string) {
    super(message);
    this.name = "SamlFlowError";
    this.code = code;
    this.status = status;
  }
}

export function samlFlowError(
  code: SamlFlowErrorCode,
  status: number,
  message: string,
): SamlFlowError {
  return new SamlFlowError(code, status, message);
}
