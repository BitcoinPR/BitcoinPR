//! Admin authorization for mutating web-explorer endpoints.
//!
//! The explorer is read-only except for `POST /api/mining/config`, which
//! changes the coinbase payout (wallet-adjacent). Mutating handlers call
//! [`authorize_admin`], which enforces two independent checks:
//!
//! 1. CSRF defense in depth: when the request carries an `Origin` header it
//!    must match the `Host` header. Browsers always attach `Origin` to
//!    cross-site POSTs, so a mismatch means the request was initiated by a
//!    foreign website; a missing `Origin` means a non-browser client (curl,
//!    scripts) or a same-origin request from an older browser.
//! 2. A bearer token: `Authorization: Bearer <token>` must match the value
//!    configured via `--webadmintoken` (or `webadmintoken=` in bitcoinpr.conf).
//!    When no token is configured, mutating endpoints are disabled entirely.

use axum::http::{header, HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

/// Constant-time byte comparison so a wrong token doesn't leak its
/// correct-prefix length via response timing.
///
/// Duplicated from `bitcoinpr-rpc/src/auth.rs` (not exported there); keep the
/// two copies in sync.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Authorize a state-changing request against the configured admin token.
///
/// Returns `Ok(())` when the request may proceed, or the `(status, body)`
/// pair the handler should return as-is.
pub fn authorize_admin(
    headers: &HeaderMap,
    token: Option<&str>,
) -> Result<(), (StatusCode, Json<Value>)> {
    // CSRF check first: an Origin header, when present, must match the Host
    // the request was sent to (Origin carries a scheme, Host does not).
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let host = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let origin_host = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .unwrap_or(origin);
        if host.is_empty() || !origin_host.eq_ignore_ascii_case(host) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "cross-origin request rejected"
                })),
            ));
        }
    }

    let Some(token) = token else {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "configuration changes are disabled: start bitcoinpr with \
                          --webadmintoken <token> (or webadmintoken= in bitcoinpr.conf) \
                          to enable them"
            })),
        ));
    };

    let expected = format!("Bearer {token}");
    let ok = headers
        .get(header::AUTHORIZATION)
        .map(|v| constant_time_eq(v.as_bytes(), expected.as_bytes()))
        .unwrap_or(false);
    if !ok {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "missing or invalid admin token (send Authorization: Bearer <token>)"
            })),
        ));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    #[test]
    fn constant_time_eq_matches() {
        assert!(constant_time_eq(b"hunter2", b"hunter2"));
        assert!(!constant_time_eq(b"hunter2", b"hunter3"));
        assert!(!constant_time_eq(b"short", b"longer-value"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn no_token_configured_forbidden() {
        let h = headers(&[("host", "localhost:3000")]);
        let err = authorize_admin(&h, None).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn missing_token_unauthorized() {
        let h = headers(&[("host", "localhost:3000")]);
        let err = authorize_admin(&h, Some("secret")).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn wrong_token_unauthorized() {
        let h = headers(&[
            ("host", "localhost:3000"),
            ("authorization", "Bearer wrong"),
        ]);
        let err = authorize_admin(&h, Some("secret")).unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn valid_token_no_origin_ok() {
        // No Origin header = non-browser client (curl) — allowed with token.
        let h = headers(&[
            ("host", "localhost:3000"),
            ("authorization", "Bearer secret"),
        ]);
        assert!(authorize_admin(&h, Some("secret")).is_ok());
    }

    #[test]
    fn valid_token_same_origin_ok() {
        let h = headers(&[
            ("host", "localhost:3000"),
            ("origin", "http://localhost:3000"),
            ("authorization", "Bearer secret"),
        ]);
        assert!(authorize_admin(&h, Some("secret")).is_ok());
    }

    #[test]
    fn cross_origin_rejected_even_with_valid_token() {
        let h = headers(&[
            ("host", "localhost:3000"),
            ("origin", "http://evil.example"),
            ("authorization", "Bearer secret"),
        ]);
        let err = authorize_admin(&h, Some("secret")).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn null_origin_rejected() {
        // Sandboxed iframes and some redirects send the literal "null" origin.
        let h = headers(&[
            ("host", "localhost:3000"),
            ("origin", "null"),
            ("authorization", "Bearer secret"),
        ]);
        let err = authorize_admin(&h, Some("secret")).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }
}
