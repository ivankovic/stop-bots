/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! The router, the middleware that guards it, and the login flow.
//!
//! # The order the guards run in
//!
//! Every request passes through, outermost first:
//!
//! 1. **`Host` allowlist.** Rejects DNS-rebinding before anything reads a
//!    cookie. First because it is the cheapest and the least conditional.
//! 2. **Security headers.** Applied to every response including errors, so
//!    a 404 is as locked down as a page.
//! 3. **Authentication.** Resolves the session cookie into an
//!    [`Authenticated`], or redirects to `/login`.
//! 4. **CSRF.** Only on state-changing methods, and only after the session
//!    is known, because the token being compared is the session's.
//!
//! Assets and the login endpoints sit outside 3 and 4 — a stylesheet
//! nobody can load makes the login page unreadable, and a login form
//! cannot present a session token it does not have yet.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Form, Router};
use maud::Markup;
use serde::Deserialize;

use crate::web::auth::{self, Authenticated, SESSION_COOKIE};
use crate::web::layout::{self, Ctx, Flash, Tab};
use crate::web::state::AppState;
use crate::web::BasePath;

/// Builds the router.
///
/// Split out from [`serve`] so tests can drive it with
/// `tower::ServiceExt::oneshot` without binding a port — the whole
/// middleware stack runs, which is the part worth testing.
pub fn router(state: AppState) -> Router {
    // Routes are registered at their *full* paths, prefix included, rather
    // than through `Router::nest`.
    //
    // `nest` looked like the obvious tool and has a sharp edge here: it
    // maps `/stop-bots` onto the inner `/` but leaves `/stop-bots/` — the
    // canonical URL, the one `BasePath::url("/")` generates and the one an
    // NGINX `location /stop-bots/` block sends — falling through to the
    // fallback as a 404. Building the paths explicitly costs one closure
    // and puts the trailing slash under this function's control.
    let path = |p: &str| state.base.url(p);

    let protected = Router::new()
        .route(&path("/"), get(crate::web::dashboard::page))
        .route(&path("/bots"), get(crate::web::bots::page))
        .route(&path("/sites"), get(crate::web::sites::page))
        .route(&path("/dynamic"), get(crate::web::dynamic::page))
        .route(&path("/help"), get(crate::web::help::page))
        .merge(crate::web::dashboard::actions(&state.base))
        .merge(crate::web::bots::actions(&state.base))
        .merge(crate::web::sites::actions(&state.base))
        .merge(crate::web::dynamic::actions(&state.base))
        .layer(middleware::from_fn_with_state(state.clone(), csrf_guard))
        .layer(middleware::from_fn_with_state(state.clone(), require_login));

    let public = Router::new()
        .route(&path("/login"), get(login_form).post(login_submit))
        .route(&path("/logout"), post(logout))
        .route(&path("/assets/style.css"), get(stylesheet))
        .route(&path("/assets/htmx.min.js"), get(htmx));

    let mut app = Router::new().merge(protected).merge(public);

    // Under a prefix, `/stop-bots` with no trailing slash is what someone
    // types. Redirect rather than serve it: one canonical URL for the
    // console keeps the session cookie's `Path` and every relative
    // reference unambiguous.
    if !state.base.is_root() {
        let canonical = state.base.url("/");
        app = app.route(
            state.base.as_str(),
            get(move || {
                let canonical = canonical.clone();
                async move { Redirect::permanent(&canonical) }
            }),
        );
    }

    app.fallback(not_found)
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            client_address,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), host_guard))
        .with_state(state)
}

/// Binds `addr` and serves until the process is stopped.
pub async fn serve(state: AppState, addr: std::net::SocketAddr) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind {addr}: {e}"))?;
    // `into_make_service_with_connect_info` is what puts the peer address
    // where `client_address` can find it, and so what makes the
    // anti-lockout guard able to recognise the browser that is asking.
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("the web server stopped: {e}"))
}

// ---- middleware ----

/// The address this request came from, as best this server can tell.
///
/// `None` when there is nothing to go on — no `ConnectInfo` (which is the
/// case when the router is driven directly in a test) and no trusted
/// forwarded header. Guards that consult it must treat `None` as "cannot
/// tell", never as "not the client".
#[derive(Debug, Clone, Default)]
pub struct ClientAddr(pub Option<String>);

/// Resolves [`ClientAddr`] once per request.
///
/// The peer address always; the leftmost `X-Forwarded-For` entry only when
/// the peer is loopback *and* the operator has said this server sits
/// behind a proxy. Both conditions, not either: the setting says a proxy
/// exists, and the loopback check says this particular request actually
/// came through something local rather than straight off the network with
/// a header someone typed.
async fn client_address(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip());

    let forwarded = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    let trusted = state
        .with_db(|db| db.get_bool_setting(crate::web::TRUST_FORWARDED_KEY, false))
        .await
        .unwrap_or(false);

    let resolved = match (trusted, peer.map(|ip| ip.is_loopback())) {
        (true, Some(true)) => forwarded.or_else(|| peer.map(|ip| ip.to_string())),
        _ => peer.map(|ip| ip.to_string()),
    };

    request.extensions_mut().insert(ClientAddr(resolved));
    next.run(request).await
}

/// Refuses a request whose `Host` this server was not told to answer to.
///
/// See [`crate::web::allowed_host`] for why this is the DNS-rebinding
/// defence rather than a tidiness check.
async fn host_guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_string();

    let configured = match state.with_db(crate::web::configured_hosts).await {
        Ok(hosts) => hosts,
        Err(err) => return internal_error(&err.to_string()),
    };

    if !crate::web::allowed_host(&host, &configured) {
        // Deliberately terse and identical for every rejected name: this
        // is the one response an attacker's page can provoke, and it
        // should teach them nothing about what *is* configured.
        return (
            StatusCode::MISDIRECTED_REQUEST,
            "This server does not answer to that host name.\n",
        )
            .into_response();
    }

    next.run(request).await
}

/// Headers applied to every response.
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // No external origins at all: every script, style and font this UI
    // uses ships in the binary. `frame-ancestors 'none'` is the
    // clickjacking defence — a console that rewrites firewall rules must
    // never be framable. `form-action 'self'` keeps a would-be injected
    // form from posting the CSRF token somewhere else.
    let csp = format!(
        "default-src 'none'; script-src 'self' {}; style-src 'self'; img-src 'self' data:; \
         connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        layout::theme_script_hash()
    );
    if let Ok(value) = HeaderValue::from_str(&csp) {
        headers.insert("content-security-policy", value);
    }
    for (name, value) in [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        // This console is not something a browser should offer to a page
        // in another tab, nor cache to disk.
        ("cache-control", "no-store"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

/// Resolves the session cookie, or sends the browser to `/login`.
async fn require_login(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let session_id = request
        .headers()
        .get(header::COOKIE)
        .and_then(|c| c.to_str().ok())
        .and_then(|c| cookie_value(c, SESSION_COOKIE));

    let Some(authenticated) = session_id.and_then(|id| state.sessions.validate(&id)) else {
        // A 303 for a form post and a 303 for a page load alike: the
        // browser should end up looking at the login page either way.
        return Redirect::to(&state.base.url("/login")).into_response();
    };

    request.extensions_mut().insert(authenticated);
    next.run(request).await
}

/// Rejects a state-changing request that did not present the session's
/// CSRF token.
///
/// Reads and re-attaches the body, because a middleware that consumes it
/// leaves the handler nothing to parse. The bodies here are small form
/// posts, so buffering one is not the memory hazard it would be on an
/// upload endpoint — and there is no upload endpoint.
async fn csrf_guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    use axum::http::Method;

    if matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        return next.run(request).await;
    }

    let Some(expected) = request.extensions().get::<Authenticated>().cloned() else {
        // `require_login` runs first, so this is unreachable in the
        // assembled router. Failing closed anyway costs nothing and means
        // a future rewiring cannot quietly turn CSRF off.
        return Redirect::to(&state.base.url("/login")).into_response();
    };

    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "form too large").into_response(),
    };

    // The header first, so a request htmx issued itself is accepted
    // without having to synthesise a form field; then the hidden input,
    // which is what an ordinary form post carries.
    let submitted = parts
        .headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| form_field(&bytes, "csrf"))
        .unwrap_or_default();
    if !auth::csrf_matches(&expected.csrf, &submitted) {
        return (
            StatusCode::FORBIDDEN,
            "This form was stale or did not come from this page. Reload and try again.\n",
        )
            .into_response();
    }

    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

// ---- login ----

#[derive(Deserialize)]
struct LoginForm {
    password: String,
}

async fn login_form(State(state): State<AppState>) -> Markup {
    layout::login_page(&state.base, None)
}

async fn login_submit(
    State(state): State<AppState>,
    Extension(client): Extension<ClientAddr>,
    Form(form): Form<LoginForm>,
) -> Response {
    // Before the hash, not after. Verifying a password is ~50ms of CPU
    // and 19MB of Argon2 working memory; letting an unauthenticated
    // caller drive that as fast as they can post is a denial of service
    // against the host this tool exists to protect. A refusal here costs
    // a map lookup.
    //
    // Keyed by client address where there is one. Behind a proxy without
    // `web:trust_forwarded_for` there is not, and everyone shares the
    // "unknown" bucket — which is exactly why the global token bucket
    // inside the throttle exists as well.
    let key = client.0.clone().unwrap_or_else(|| "unknown".to_string());
    if let Err(throttled) = state.login_throttle.check(&key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(
                header::RETRY_AFTER,
                throttled.retry_after.as_secs().max(1).to_string(),
            )],
            Html(layout::login_page(&state.base, Some(throttled.message)).into_string()),
        )
            .into_response();
    }

    let password = form.password;
    let verified = state
        .with_db(move |db| auth::verify_password(db, &password))
        .await;

    let secure = state
        .with_db(|db| db.get_bool_setting(crate::web::SECURE_COOKIE_KEY, false))
        .await
        .unwrap_or(false);

    match verified {
        Ok(true) => match state.sessions.create() {
            Ok((id, _csrf)) => (
                [(header::SET_COOKIE, session_cookie(&id, secure, &state.base))],
                Redirect::to(&state.base.url("/")),
            )
                .into_response(),
            Err(err) => internal_error(&err.to_string()),
        },
        // One message for a wrong password and for no password having been
        // set: neither is worth confirming to whoever is guessing.
        Ok(false) => {
            state.login_throttle.record_failure(&key);
            (
                StatusCode::UNAUTHORIZED,
                Html(
                    layout::login_page(&state.base, Some("That password was not accepted."))
                        .into_string(),
                ),
            )
                .into_response()
        }
        Err(err) => internal_error(&err.to_string()),
    }
}

/// Ends the session server-side, not merely in the browser.
///
/// Outside the CSRF guard on purpose: a forged logout is a nuisance, not a
/// vulnerability, and requiring a token here would mean an expired session
/// could not be cleared without one.
async fn logout(State(state): State<AppState>, request: Request) -> Response {
    if let Some(id) = request
        .headers()
        .get(header::COOKIE)
        .and_then(|c| c.to_str().ok())
        .and_then(|c| cookie_value(c, SESSION_COOKIE))
    {
        state.sessions.remove(&id);
    }
    (
        [(header::SET_COOKIE, expired_cookie(&state.base))],
        Redirect::to("/login"),
    )
        .into_response()
}

/// The `Set-Cookie` value for a fresh session.
///
/// `HttpOnly` so script cannot read it, `SameSite=Strict` so the browser
/// will not attach it to a request another site started — belt to the CSRF
/// token's braces — and `Path=/` because every route needs it.
///
/// `Secure` is opt-in rather than always on, and the default is off,
/// because the default deployment is plain HTTP on loopback: a `Secure`
/// cookie is never stored there, so the console would take a correct
/// password and bounce straight back to the login page. Behind TLS it
/// should be on — `web:secure_cookie` — or a browser will send the session
/// to an `http://` URL for the same host.
fn session_cookie(id: &str, secure: bool, base: &BasePath) -> String {
    let mut cookie = format!(
        "{SESSION_COOKIE}={id}; HttpOnly; SameSite=Strict; Path={}",
        base.cookie_path()
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn expired_cookie(base: &BasePath) -> String {
    format!(
        "{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path={}; Max-Age=0",
        base.cookie_path()
    )
}

/// Pulls one cookie's value out of a `Cookie` header.
pub fn cookie_value(header: &str, name: &str) -> Option<String> {
    header.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key.trim() == name).then(|| value.trim().to_string())
    })
}

/// Pulls one field out of an `application/x-www-form-urlencoded` body.
///
/// Only used for the CSRF token, which the guard has to read before the
/// handler's own `Form` extractor gets the body.
fn form_field(body: &[u8], name: &str) -> Option<String> {
    let body = std::str::from_utf8(body).ok()?;
    body.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (percent_decode(key) == name).then(|| percent_decode(value))
    })
}

/// Minimal `application/x-www-form-urlencoded` decoding: `+` is a space
/// and `%XX` is a byte.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    None => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---- assets ----

async fn stylesheet() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("assets/style.css"),
    )
}

async fn htmx() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("assets/htmx.min.js"),
    )
}

// ---- errors ----

async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Not found\n").into_response()
}

/// A 500 that says what went wrong.
///
/// The audience for this UI is one operator with root on the box, who can
/// read the same error out of the logs anyway; hiding it would only cost
/// them a debugging round-trip.
pub fn internal_error(message: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(
            layout::page(
                Tab::Dashboard,
                &Ctx::for_tests(),
                Some(Flash::err(message)),
                maud::html! { p { "The request could not be completed." } },
            )
            .into_string(),
        ),
    )
        .into_response()
}

/// Renders `content` as a full page, with the session's CSRF token
/// available to the caller.
pub fn render(tab: Tab, ctx: &Ctx, flash: Option<Flash>, content: Markup) -> Response {
    Html(layout::page(tab, ctx, flash, content).into_string()).into_response()
}

/// The `Authenticated` an inner handler is guaranteed to have.
pub type Auth = Extension<Authenticated>;

/// Shared by the action handlers: a flash message survives one redirect by
/// riding in the query string.
///
/// A cookie would be the other way and is worse here: it needs a
/// clear-on-read dance, it lands on every subsequent request until it is
/// cleared, and the message is not secret — it is what the operator just
/// did, and they are about to read it on screen.
pub fn back_with(base: &BasePath, path: &str, message: &str, ok: bool) -> Response {
    let kind = if ok { "ok" } else { "err" };
    Redirect::to(&format!(
        "{}?flash={}&kind={kind}",
        base.url(path),
        percent_encode(message)
    ))
    .into_response()
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The flash a redirect left in the query string.
#[derive(Debug, Default, Deserialize)]
pub struct FlashQuery {
    pub flash: Option<String>,
    pub kind: Option<String>,
}

impl FlashQuery {
    pub fn into_flash(self) -> Option<Flash> {
        let text = self.flash?;
        Some(if self.kind.as_deref() == Some("err") {
            Flash::err(text)
        } else {
            Flash::ok(text)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cookie_value_is_found_among_others() {
        let header = "theme=dark; stop_bots_session=abc123; other=x";
        assert_eq!(
            cookie_value(header, SESSION_COOKIE).as_deref(),
            Some("abc123")
        );
        assert_eq!(cookie_value(header, "theme").as_deref(), Some("dark"));
        assert_eq!(cookie_value(header, "absent"), None);
    }

    #[test]
    fn a_cookie_name_must_match_exactly() {
        // `stop_bots_session_extra` must not satisfy a lookup for
        // `stop_bots_session`.
        let header = "stop_bots_session_extra=nope";
        assert_eq!(cookie_value(header, SESSION_COOKIE), None);
    }

    #[test]
    fn the_session_cookie_carries_the_flags_that_make_it_safe() {
        let cookie = session_cookie("a-session-id", false, &BasePath::default());
        for flag in ["HttpOnly", "SameSite=Strict", "Path=/"] {
            assert!(cookie.contains(flag), "missing {flag} in: {cookie}");
        }
    }

    #[test]
    fn secure_is_opt_in_because_the_default_deployment_is_plain_http() {
        assert!(
            !session_cookie("id", false, &BasePath::default()).contains("Secure"),
            "a Secure cookie is never stored over plain HTTP, so the default must not set it"
        );
        assert!(session_cookie("id", true, &BasePath::default()).contains("; Secure"));
    }

    #[test]
    fn logging_out_sends_a_cookie_that_expires_immediately() {
        assert!(expired_cookie(&BasePath::default()).contains("Max-Age=0"));
    }

    #[test]
    fn a_form_field_is_decoded_from_the_body() {
        let body = b"csrf=abc%2D123&password=hunter2";
        assert_eq!(form_field(body, "csrf").as_deref(), Some("abc-123"));
        assert_eq!(form_field(body, "password").as_deref(), Some("hunter2"));
        assert_eq!(form_field(body, "absent"), None);
    }

    #[test]
    fn form_decoding_handles_plus_and_percent_escapes() {
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("%2F"), "/");
        assert_eq!(percent_decode("plain"), "plain");
        // A truncated escape is left alone rather than swallowing the
        // characters after it.
        assert_eq!(percent_decode("%2"), "%2");
    }

    #[test]
    fn percent_encoding_round_trips_a_message_with_punctuation() {
        let message = "Blocked 192.0.2.1 — done & applied?";
        assert_eq!(percent_decode(&percent_encode(message)), message);
    }

    #[test]
    fn a_flash_query_without_a_message_is_no_flash() {
        assert!(FlashQuery::default().into_flash().is_none());
    }

    #[test]
    fn a_flash_query_kind_selects_the_colour() {
        let ok = FlashQuery {
            flash: Some("saved".into()),
            kind: Some("ok".into()),
        }
        .into_flash()
        .unwrap();
        assert!(ok.ok);

        let err = FlashQuery {
            flash: Some("nope".into()),
            kind: Some("err".into()),
        }
        .into_flash()
        .unwrap();
        assert!(!err.ok);
    }
}
