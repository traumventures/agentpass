//! Localhost web server for the passkey pages (the embedded Yew app) and its
//! small JSON API.
//!
//! Defences: listens on 127.0.0.1 only; rejects foreign `Host` headers (DNS
//! rebinding); requires `Origin: http://localhost:<port>` for POSTs; every
//! API call needs the one-time flow token, which travels in the URL fragment
//! (never sent to servers or logged); strict CSP and no-store caching.

use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use include_dir::{include_dir, Dir};
use sha2::{Digest, Sha256};

use super::{log, Daemon, Fail};
use crate::crypto;
use crate::ipc::ErrorCode;
use agentpass_protocol as proto;

static ASSETS: Dir<'static> = include_dir!("$OUT_DIR/web");

pub async fn serve(d: Arc<Daemon>, listener: tokio::net::TcpListener) {
    if let Err(e) = axum::serve(listener, router(d)).await {
        log!("web server stopped: {e}");
    }
}

pub fn router(d: Arc<Daemon>) -> Router {
    Router::new()
        .route("/api/flow", get(flow_info))
        .route("/api/flow/complete", post(flow_complete))
        .fallback(get(asset))
        .layer(middleware::from_fn_with_state(d.clone(), guard))
        .with_state(d)
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(proto::ApiError {
            error: message.into(),
        }),
    )
        .into_response()
}

impl IntoResponse for Fail {
    fn into_response(self) -> Response {
        let status = match self.code {
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::Invalid => StatusCode::BAD_REQUEST,
            ErrorCode::Locked => StatusCode::CONFLICT,
            ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        error(status, self.message)
    }
}

/// Accepts `localhost` / `127.0.0.1` / `[::1]` with any port, so the page also
/// works through port forwarding (e.g. `ssh -L 9000:localhost:47117`).
/// Rejecting other host names is what stops DNS rebinding.
pub(crate) fn local_host(host: &str) -> bool {
    let name = match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => host,
    };
    matches!(name, "localhost" | "127.0.0.1" | "[::1]")
}

async fn guard(State(_d): State<Arc<Daemon>>, req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_owned();
    if !local_host(&host) {
        return error(StatusCode::MISDIRECTED_REQUEST, "unexpected Host header");
    }
    if req.method() != Method::GET && req.method() != Method::HEAD {
        // Same-origin only: the Origin must be exactly the page's own origin.
        let origin_ok = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|o| o == format!("http://{host}"));
        if !origin_ok {
            return error(StatusCode::FORBIDDEN, "cross-origin request rejected");
        }
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    resp
}

fn flow_token(headers: &HeaderMap) -> Result<&str, Fail> {
    headers
        .get(proto::TOKEN_HEADER)
        .and_then(|h| h.to_str().ok())
        .filter(|t| !t.is_empty())
        .ok_or(Fail {
            code: ErrorCode::Invalid,
            message: "missing flow token; open the full link printed by agentpass".into(),
        })
}

async fn flow_info(
    State(d): State<Arc<Daemon>>,
    headers: HeaderMap,
) -> Result<Json<proto::FlowInfo>, Fail> {
    Ok(Json(d.flow_info(flow_token(&headers)?)?))
}

async fn flow_complete(
    State(d): State<Arc<Daemon>>,
    headers: HeaderMap,
    Json(body): Json<proto::FlowCompletion>,
) -> Result<Json<proto::FlowResult>, Fail> {
    let token = flow_token(&headers)?.to_owned();
    let message = tokio::task::spawn_blocking(move || d.complete_flow(&token, body))
        .await
        .map_err(Fail::internal)??;
    Ok(Json(proto::FlowResult { message }))
}

/// index.html plus the CSP that allows exactly its inline scripts.
fn index() -> &'static (String, String) {
    static INDEX: OnceLock<(String, String)> = OnceLock::new();
    INDEX.get_or_init(|| {
        let html = ASSETS
            .get_file("index.html")
            .and_then(|f| f.contents_utf8())
            .unwrap_or("<!doctype html><title>agentpass</title><p>web UI missing")
            .to_owned();
        let hashes: Vec<String> = inline_scripts(&html)
            .map(|s| format!("'sha256-{}'", crypto::b64(&Sha256::digest(s.as_bytes()))))
            .collect();
        let csp = format!(
            "default-src 'none'; script-src 'self' 'wasm-unsafe-eval' {}; style-src 'self'; \
             img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; \
             frame-ancestors 'none'",
            hashes.join(" ")
        );
        (html, csp)
    })
}

/// Bodies of `<script>` elements without a `src` attribute.
fn inline_scripts(html: &str) -> impl Iterator<Item = &str> {
    let mut rest = html;
    std::iter::from_fn(move || loop {
        let start = rest.find("<script")?;
        let tag_end = start + rest[start..].find('>')?;
        let tag = &rest[start..tag_end];
        let body_start = tag_end + 1;
        let body_end = body_start + rest[body_start..].find("</script>")?;
        let body = &rest[body_start..body_end];
        rest = &rest[body_end + "</script>".len()..];
        if !tag.contains(" src=") {
            return Some(body);
        }
    })
}

async fn asset(req: Request) -> Response {
    let path = req.uri().path();
    if matches!(path, "/" | "/setup" | "/unlock" | "/enroll") {
        let (html, csp) = index();
        return Response::builder()
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CONTENT_SECURITY_POLICY, csp.as_str())
            .body(Body::from(html.as_str()))
            .unwrap();
    }
    let name = path.trim_start_matches('/');
    match ASSETS.get_file(name).filter(|_| name != "index.html") {
        Some(f) => {
            let mime = mime_guess::from_path(name).first_or_octet_stream();
            Response::builder()
                .header(header::CONTENT_TYPE, mime.as_ref())
                .body(Body::from(f.contents()))
                .unwrap()
        }
        None => error(StatusCode::NOT_FOUND, "not found"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_hosts_on_any_port() {
        for ok in [
            "localhost:47117",
            "localhost:53273",
            "127.0.0.1:1",
            "[::1]:80",
            "localhost",
        ] {
            assert!(local_host(ok), "{ok}");
        }
        for bad in [
            "evil.example:47117",
            "localhost.evil.example:1",
            "127.0.0.2:47117",
            "",
        ] {
            assert!(!local_host(bad), "{bad}");
        }
    }

    #[test]
    fn finds_inline_scripts_only() {
        let html = r#"<head><script type="module">import x from "/a.js";</script>
<script src="/b.js"></script><script>b()</script></head>"#;
        let found: Vec<&str> = inline_scripts(html).collect();
        assert_eq!(found, vec![r#"import x from "/a.js";"#, "b()"]);
    }
}
