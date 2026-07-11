//! HTTP Basic authentication middleware for the JSON-RPC server.
//!
//! jsonrpsee exposes an HTTP-level tower middleware hook (`set_http_middleware`)
//! that sees the raw `http::Request` before it is dispatched to a method. We use
//! it to reject any request whose `Authorization` header does not match the
//! configured `rpcuser:rpcpassword`, so control-plane methods like `stop`,
//! `sendrawtransaction`, and `generatetoaddress` are not exposed unauthenticated.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use base64::Engine;
use http::{header, Request, Response, StatusCode};
use jsonrpsee::server::HttpBody;
use tower::{Layer, Service};

/// Tower layer enforcing HTTP Basic auth for the RPC server.
#[derive(Clone)]
pub struct AuthLayer {
    /// Expected full `Authorization` header value (`Basic <base64(user:pass)>`).
    /// `None` disables authentication (all requests pass through).
    expected: Arc<Option<String>>,
}

impl AuthLayer {
    /// Build the layer from raw `user:password` credentials. When `credentials`
    /// is `None`, authentication is disabled.
    pub fn new(credentials: Option<&str>) -> Self {
        let expected = credentials.map(|creds| {
            let encoded = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
            format!("Basic {encoded}")
        });
        AuthLayer {
            expected: Arc::new(expected),
        }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            expected: self.expected.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    expected: Arc<Option<String>>,
}

/// Constant-time byte comparison so a wrong credential doesn't leak its
/// correct-prefix length via response timing.
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

impl<S, B> Service<Request<B>> for AuthService<S>
where
    S: Service<Request<B>, Response = Response<HttpBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let expected = self.expected.clone();
        // tower contract: the future must use the `inner` that was readied in
        // `poll_ready`. Swap in a fresh clone and move the readied one into the
        // future. (https://docs.rs/tower/latest/tower/trait.Service.html)
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            if let Some(expected) = expected.as_ref() {
                let ok = req
                    .headers()
                    .get(header::AUTHORIZATION)
                    .map(|v| constant_time_eq(v.as_bytes(), expected.as_bytes()))
                    .unwrap_or(false);

                if !ok {
                    let resp = Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header(header::WWW_AUTHENTICATE, "Basic realm=\"bitcoinpr\"")
                        .body(HttpBody::from("401 Unauthorized\n"))
                        .expect("static 401 response is always valid");
                    return Ok(resp);
                }
            }
            inner.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches() {
        assert!(constant_time_eq(b"hunter2", b"hunter2"));
        assert!(!constant_time_eq(b"hunter2", b"hunter3"));
        assert!(!constant_time_eq(b"short", b"longer-value"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn auth_layer_encodes_basic_header() {
        let layer = AuthLayer::new(Some("test:test"));
        // base64("test:test") == "dGVzdDp0ZXN0"
        assert_eq!(
            layer.expected.as_ref().as_deref(),
            Some("Basic dGVzdDp0ZXN0")
        );
    }

    #[test]
    fn auth_layer_none_disables() {
        let layer = AuthLayer::new(None);
        assert!(layer.expected.as_ref().is_none());
    }
}
