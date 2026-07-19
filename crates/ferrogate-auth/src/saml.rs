// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! SAML 2.0 SP-initiated login over the HTTP-Redirect binding (issue #283).
//!
//! Binding choice: this implements the **HTTP-Redirect binding** for both the
//! outbound `AuthnRequest` and the inbound `Response`, whose signature is a
//! *detached* RSA signature over the URL query octet string
//! (`SAMLResponse=..&RelayState=..&SigAlg=..`), per the SAML 2.0 Bindings spec
//! §3.4.4.1. That deliberately avoids XML Digital Signature canonicalization
//! (exclusive C14N) entirely: we verify the signature against the IdP's X.509
//! certificate with maintained, pure-Rust crates (`ring` for RSA verification,
//! `x509-parser` for the key), and only THEN parse the now-authenticated XML
//! with `quick-xml`. No hand-rolled XML-dsig crypto, and no heavy native
//! `xmlsec`/`libxml` dependency (the alternative `samael` crate's transitive
//! requirement).
//!
//! Everything fails closed: a missing/invalid signature, an unsupported
//! `SigAlg`, a non-`Success` status, an issuer/audience mismatch, an
//! `InResponseTo` mismatch, an out-of-window `Conditions` time (clock-skew
//! adjusted), or a missing usable email are all hard rejections.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use quick_xml::events::Event;
use quick_xml::Reader;
use ring::signature;

const SIG_ALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SIG_ALG_RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const HTTP_REDIRECT_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

fn base64_standard() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Strips optional PEM armor and whitespace, returning the raw DER bytes of an
/// X.509 certificate supplied as PEM or bare base64.
fn certificate_der(cert: &str) -> Result<Vec<u8>, String> {
    let trimmed = cert.trim();
    let base64_body = if trimmed.contains("BEGIN CERTIFICATE") {
        trimmed
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>()
    } else {
        trimmed.split_whitespace().collect::<String>()
    };
    base64_standard()
        .decode(base64_body.as_bytes())
        .map_err(|error| format!("certificate is not valid base64: {error}"))
}

/// Parses the IdP signing certificate and returns the DER-encoded PKCS#1
/// `RSAPublicKey` bytes that `ring` expects. Fails closed for a non-RSA or
/// unparseable certificate.
pub fn parse_idp_public_key(cert: &str) -> Result<Vec<u8>, String> {
    use x509_parser::prelude::FromDer;

    let der = certificate_der(cert)?;
    let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(&der)
        .map_err(|error| format!("invalid X.509 certificate: {error}"))?;
    let spki = certificate.public_key();
    // For an RSA key the SubjectPublicKeyInfo's subjectPublicKey BIT STRING
    // content IS the DER of `RSAPublicKey ::= SEQUENCE { modulus, exponent }`,
    // which is exactly the format `ring`'s RSA verifier consumes.
    let key = spki.subject_public_key.data.as_ref().to_vec();
    if key.is_empty() {
        return Err("certificate has an empty public key".to_string());
    }
    Ok(key)
}

/// Minimal XML text/attribute escaping for the values we place into the
/// outbound `AuthnRequest`.
fn xml_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Builds the SP-initiated `AuthnRequest`, DEFLATE-compresses + base64-encodes
/// it per the HTTP-Redirect binding, and returns the full IdP redirect URL
/// (`...?SAMLRequest=..&RelayState=..`). We do not sign our own request; IdPs
/// that require signed requests are out of scope for this slice.
pub fn build_authn_request_redirect(
    idp_sso_url: &str,
    acs_url: &str,
    sp_entity_id: &str,
    request_id: &str,
    relay_state: &str,
) -> anyhow::Result<String> {
    let issue_instant = format_saml_instant(now_unix());
    let xml = format!(
        "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{id}\" Version=\"2.0\" \
         IssueInstant=\"{instant}\" Destination=\"{destination}\" ProtocolBinding=\"{binding}\" \
         AssertionConsumerServiceURL=\"{acs}\"><saml:Issuer>{issuer}</saml:Issuer>\
         </samlp:AuthnRequest>",
        id = xml_escape(request_id),
        instant = issue_instant,
        destination = xml_escape(idp_sso_url),
        binding = HTTP_REDIRECT_BINDING,
        acs = xml_escape(acs_url),
        issuer = xml_escape(sp_entity_id),
    );

    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(xml.as_bytes())?;
    let compressed = encoder.finish()?;
    let encoded = base64_standard().encode(compressed);

    let separator = if idp_sso_url.contains('?') { '&' } else { '?' };
    Ok(format!(
        "{idp_sso_url}{separator}SAMLRequest={}&RelayState={}",
        super::urlencode(&encoded),
        super::urlencode(relay_state),
    ))
}

/// Parsed HTTP-Redirect binding query parameters. The `*_raw` fields preserve
/// the exact percent-encoded octets as received, which the redirect-binding
/// signature is computed over; the decoded convenience fields are for lookups
/// and payload decoding.
pub struct RedirectBindingParams {
    /// URL-decoded base64 `SAMLResponse` (still DEFLATE-compressed).
    pub saml_response: Option<String>,
    /// URL-decoded `RelayState` (our opaque flow `state` token).
    pub relay_state: Option<String>,
    saml_response_raw: Option<String>,
    relay_state_raw: Option<String>,
    sig_alg_raw: Option<String>,
    signature_raw: Option<String>,
}

impl RedirectBindingParams {
    /// Splits the raw query string, preserving each value's original
    /// percent-encoding (no decode) so the signed octet string can be
    /// reconstructed byte-for-byte.
    pub fn parse(raw_query: &str) -> Self {
        let mut saml_response_raw = None;
        let mut relay_state_raw = None;
        let mut sig_alg_raw = None;
        let mut signature_raw = None;
        for pair in raw_query.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            match key {
                "SAMLResponse" => saml_response_raw = Some(value.to_string()),
                "RelayState" => relay_state_raw = Some(value.to_string()),
                "SigAlg" => sig_alg_raw = Some(value.to_string()),
                "Signature" => signature_raw = Some(value.to_string()),
                _ => {}
            }
        }
        Self {
            saml_response: saml_response_raw.as_deref().map(super::urldecode),
            relay_state: relay_state_raw.as_deref().map(super::urldecode),
            saml_response_raw,
            relay_state_raw,
            sig_alg_raw,
            signature_raw,
        }
    }

    /// The exact octet string the IdP signed, reconstructed from the received
    /// raw values in the binding's fixed order.
    fn signed_octet_string(&self) -> Result<String, String> {
        let saml_response = self
            .saml_response_raw
            .as_deref()
            .ok_or("missing SAMLResponse")?;
        let sig_alg = self.sig_alg_raw.as_deref().ok_or("missing SigAlg")?;
        let mut signed = format!("SAMLResponse={saml_response}");
        if let Some(relay_state) = self.relay_state_raw.as_deref() {
            signed.push_str(&format!("&RelayState={relay_state}"));
        }
        signed.push_str(&format!("&SigAlg={sig_alg}"));
        Ok(signed)
    }
}

/// Verifies the HTTP-Redirect binding signature against the IdP certificate.
/// Fails closed on a missing signature, an unsupported `SigAlg`, or a
/// verification failure.
pub fn verify_redirect_signature(
    params: &RedirectBindingParams,
    certificate: &str,
) -> Result<(), String> {
    let signature_raw = params
        .signature_raw
        .as_deref()
        .ok_or("response is not signed (no Signature parameter)")?;
    let sig_alg = params
        .sig_alg_raw
        .as_deref()
        .map(super::urldecode)
        .ok_or("missing SigAlg")?;
    let algorithm: &dyn signature::VerificationAlgorithm = match sig_alg.as_str() {
        SIG_ALG_RSA_SHA256 => &signature::RSA_PKCS1_2048_8192_SHA256,
        SIG_ALG_RSA_SHA1 => &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
        other => return Err(format!("unsupported SigAlg {other:?}")),
    };

    let signature_bytes = base64_standard()
        .decode(super::urldecode(signature_raw).as_bytes())
        .map_err(|error| format!("signature is not valid base64: {error}"))?;
    let signed = params.signed_octet_string()?;
    let public_key_der = parse_idp_public_key(certificate)?;

    signature::UnparsedPublicKey::new(algorithm, &public_key_der)
        .verify(signed.as_bytes(), &signature_bytes)
        .map_err(|_| "signature does not verify against the IdP certificate".to_string())
}

/// What a valid assertion must satisfy, plus the attribute names to read.
pub struct AssertionExpectations<'a> {
    pub sp_entity_id: &'a str,
    pub idp_entity_id: Option<&'a str>,
    pub in_response_to: Option<&'a str>,
    pub email_attribute: Option<&'a str>,
    pub name_attribute: Option<&'a str>,
    pub groups_attribute: Option<&'a str>,
    pub now_unix: i64,
    pub clock_skew_secs: i64,
}

/// The identity extracted from a verified, validated assertion.
#[derive(Debug)]
pub struct ValidatedAssertion {
    pub email: String,
    pub display_name: String,
    pub groups: Vec<String>,
}

#[derive(Default)]
struct ParsedResponse {
    status_code: Option<String>,
    response_in_response_to: Option<String>,
    issuer: Option<String>,
    not_before: Option<String>,
    not_on_or_after: Option<String>,
    audiences: Vec<String>,
    name_id: Option<String>,
    attributes: BTreeMap<String, Vec<String>>,
}

fn local_name(name: quick_xml::name::QName<'_>) -> String {
    String::from_utf8_lossy(name.local_name().as_ref()).into_owned()
}

fn attribute_value(element: &quick_xml::events::BytesStart<'_>, wanted: &str) -> Option<String> {
    element.attributes().flatten().find_map(|attribute| {
        if local_name(attribute.key) == wanted {
            attribute
                .unescape_value()
                .ok()
                .map(|value| value.into_owned())
        } else {
            None
        }
    })
}

/// Captures the attributes we care about from a `Start`/`Empty` element.
fn capture_element(
    parsed: &mut ParsedResponse,
    current_attribute: &mut Option<String>,
    name: &str,
    element: &quick_xml::events::BytesStart<'_>,
) {
    match name {
        "Response" => {
            parsed.response_in_response_to = attribute_value(element, "InResponseTo");
        }
        "StatusCode" if parsed.status_code.is_none() => {
            parsed.status_code = attribute_value(element, "Value");
        }
        "Conditions" => {
            parsed.not_before = attribute_value(element, "NotBefore");
            parsed.not_on_or_after = attribute_value(element, "NotOnOrAfter");
        }
        "Attribute" => {
            *current_attribute = attribute_value(element, "Name")
                .or_else(|| attribute_value(element, "FriendlyName"));
        }
        _ => {}
    }
}

/// Parses the DEFLATE+base64 `SAMLResponse` into the fields we care about. The
/// bytes are already authenticated by the redirect-binding signature, so this
/// operates on trusted input.
fn parse_response_xml(saml_response_b64: &str) -> Result<ParsedResponse, String> {
    let compressed = base64_standard()
        .decode(saml_response_b64.as_bytes())
        .map_err(|error| format!("SAMLResponse is not valid base64: {error}"))?;
    let mut xml = Vec::new();
    DeflateDecoder::new(&compressed[..])
        .read_to_end(&mut xml)
        .map_err(|error| format!("SAMLResponse could not be inflated: {error}"))?;

    let mut reader = Reader::from_reader(xml.as_slice());
    let mut parsed = ParsedResponse::default();
    let mut stack: Vec<String> = Vec::new();
    let mut current_attribute: Option<String> = None;
    let mut buffer = Vec::new();

    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element)) => {
                let name = local_name(element.name());
                capture_element(&mut parsed, &mut current_attribute, &name, &element);
                // `Start` elements have children and a matching `End`, so track
                // them on the stack.
                stack.push(name);
            }
            Ok(Event::Empty(element)) => {
                // Self-closing elements never emit a matching `End`, so do not
                // push them onto the stack.
                let name = local_name(element.name());
                capture_element(&mut parsed, &mut current_attribute, &name, &element);
            }
            Ok(Event::Text(text)) => {
                let value = text
                    .unescape()
                    .map(|value| value.trim().to_string())
                    .unwrap_or_default();
                if value.is_empty() {
                    continue;
                }
                match stack.last().map(String::as_str) {
                    Some("Issuer") if parsed.issuer.is_none() => parsed.issuer = Some(value),
                    Some("Audience") => parsed.audiences.push(value),
                    Some("NameID") => parsed.name_id = Some(value),
                    Some("AttributeValue") => {
                        if let Some(name) = &current_attribute {
                            parsed
                                .attributes
                                .entry(name.clone())
                                .or_default()
                                .push(value);
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(element)) => {
                let name = local_name(element.name());
                if name == "Attribute" {
                    current_attribute = None;
                }
                stack.pop();
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(format!("malformed SAML XML: {error}")),
            _ => {}
        }
        buffer.clear();
    }

    Ok(parsed)
}

/// Validates a parsed response against the expectations and extracts the
/// caller identity. Every failure is a hard rejection.
pub fn parse_and_validate_response(
    saml_response_b64: &str,
    expectations: &AssertionExpectations,
) -> Result<ValidatedAssertion, String> {
    let parsed = parse_response_xml(saml_response_b64)?;

    if parsed.status_code.as_deref() != Some(STATUS_SUCCESS) {
        return Err(format!(
            "status is not Success (got {:?})",
            parsed.status_code
        ));
    }
    if let Some(expected) = expectations.in_response_to {
        if parsed.response_in_response_to.as_deref() != Some(expected) {
            return Err("InResponseTo does not match the pending AuthnRequest".to_string());
        }
    }
    if let Some(expected_issuer) = expectations.idp_entity_id {
        if parsed.issuer.as_deref() != Some(expected_issuer) {
            return Err("assertion Issuer does not match the configured IdP entity id".to_string());
        }
    }
    if !parsed
        .audiences
        .iter()
        .any(|audience| audience == expectations.sp_entity_id)
    {
        return Err("assertion audience does not include this SP".to_string());
    }
    if let Some(not_before) = parsed.not_before.as_deref() {
        let not_before = parse_saml_instant(not_before)?;
        if expectations.now_unix + expectations.clock_skew_secs < not_before {
            return Err("assertion is not yet valid (NotBefore)".to_string());
        }
    }
    if let Some(not_on_or_after) = parsed.not_on_or_after.as_deref() {
        let not_on_or_after = parse_saml_instant(not_on_or_after)?;
        if expectations.now_unix - expectations.clock_skew_secs >= not_on_or_after {
            return Err("assertion has expired (NotOnOrAfter)".to_string());
        }
    }

    let first_attribute = |name: &str| -> Option<String> {
        parsed
            .attributes
            .get(name)
            .and_then(|values| values.first())
            .cloned()
    };

    // Email: prefer the configured attribute, then common conventions, then
    // the Subject NameID (frequently the email itself). Fail closed if none is
    // a usable address.
    let email = expectations
        .email_attribute
        .and_then(first_attribute)
        .or_else(|| first_attribute("email"))
        .or_else(|| first_attribute("mail"))
        .or_else(|| {
            first_attribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
        })
        .or_else(|| parsed.name_id.clone())
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| super::is_valid_email(value));
    let email = email.ok_or("assertion did not include a usable email")?;

    let display_name = expectations
        .name_attribute
        .and_then(first_attribute)
        .or_else(|| first_attribute("displayName"))
        .or_else(|| first_attribute("name"))
        .unwrap_or_else(|| email.clone());

    let groups_attribute = expectations.groups_attribute.unwrap_or("groups");
    let groups = parsed
        .attributes
        .get(groups_attribute)
        .cloned()
        .unwrap_or_default();

    Ok(ValidatedAssertion {
        email,
        display_name,
        groups,
    })
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// Days from the civil date to the Unix epoch (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = (if year >= 0 { year } else { year - 399 }) / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Formats a Unix second as a SAML/XSD UTC dateTime (`YYYY-MM-DDTHH:MM:SSZ`).
fn format_saml_instant(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (seconds / 3600, (seconds % 3600) / 60, seconds % 60);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Parses a SAML/XSD UTC dateTime into a Unix second. Requires the trailing
/// `Z` (UTC); fractional seconds are tolerated and ignored. Fails closed on
/// anything else.
fn parse_saml_instant(value: &str) -> Result<i64, String> {
    let value = value.trim();
    let stripped = value
        .strip_suffix('Z')
        .ok_or_else(|| format!("SAML instant {value:?} is not UTC (missing trailing Z)"))?;
    let (date, time) = stripped
        .split_once('T')
        .ok_or_else(|| format!("SAML instant {value:?} is missing the time component"))?;
    let time = time.split('.').next().unwrap_or(time);

    let mut date_parts = date.split('-');
    let year: i64 = parse_field(date_parts.next(), "year")?;
    let month: i64 = parse_field(date_parts.next(), "month")?;
    let day: i64 = parse_field(date_parts.next(), "day")?;

    let mut time_parts = time.split(':');
    let hour: i64 = parse_field(time_parts.next(), "hour")?;
    let minute: i64 = parse_field(time_parts.next(), "minute")?;
    let second: i64 = parse_field(time_parts.next(), "second")?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(format!("SAML instant {value:?} has an out-of-range date"));
    }

    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

fn parse_field(part: Option<&str>, name: &str) -> Result<i64, String> {
    part.ok_or_else(|| format!("SAML instant is missing the {name}"))?
        .parse::<i64>()
        .map_err(|error| format!("SAML instant has an invalid {name}: {error}"))
}

#[cfg(test)]
mod tests;
