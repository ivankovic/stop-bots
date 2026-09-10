//! The web UI's guards, driven through the assembled router.
//!
//! `tower::ServiceExt::oneshot` runs the real middleware stack — host
//! check, security headers, session lookup, CSRF — without binding a port.
//! That is deliberate: the properties worth asserting here are all
//! decisions those layers make, and a real listener would only add a port
//! to collide on and a server to shut down.
//!
//! Every test drives HTTP the way a browser would, because the thing under
//! test *is* the HTTP behaviour. There are no mocks: the database is a
//! real SQLite one on a tempdir, and the password is really hashed with
//! Argon2 and really verified.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use stop_bots::db::Db;
use stop_bots::web::server;
use stop_bots::web::state::AppState;
use tower::ServiceExt;

/// A router over a fresh database, plus the password that opens it.
fn app() -> (Router, String, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(tmp.path().join("db.sqlite3")).unwrap();
    let password = stop_bots::web::auth::generate_password().unwrap();
    stop_bots::web::auth::set_password(&db, &password).unwrap();

    // `apply_for_real: false` throughout — a test must never reload the
    // developer's NGINX or run a firewall script at them.
    let state = AppState::new(db, tmp.path().join("nginx"), None, false);
    (server::router(state), password, tmp)
}

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header(header::HOST, "localhost")
        .body(Body::empty())
        .unwrap()
}

fn post(path: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn with_cookie(mut request: Request<Body>, cookie: &str) -> Request<Body> {
    request
        .headers_mut()
        .insert(header::COOKIE, cookie.parse().unwrap());
    request
}

async fn body_string(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn session_cookie_from(response: &Response) -> String {
    let set = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("a successful login sets a cookie")
        .to_str()
        .unwrap();
    set.split(';').next().unwrap().to_string()
}

/// Logs in and returns the session cookie plus that session's CSRF token,
/// read back out of a rendered form.
async fn login(app: &Router, password: &str) -> (String, String) {
    let response = app
        .clone()
        .oneshot(post("/login", &format!("password={password}")))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "a correct password should redirect into the app"
    );
    let cookie = session_cookie_from(&response);

    // From the meta tag rather than a form field: every authenticated
    // page carries it, whereas a form only appears once there is a row to
    // act on, and these tests start from an empty database.
    let page = app
        .clone()
        .oneshot(with_cookie(get("/dynamic"), &cookie))
        .await
        .unwrap();
    let html = body_string(page).await;
    let csrf = html
        .split(r#"<meta name="csrf-token" content=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("every authenticated page carries the token")
        .to_string();

    (cookie, csrf)
}

// ---- reaching it at all ----

#[tokio::test]
async fn an_unauthenticated_request_is_sent_to_the_login_page() {
    let (app, _password, _tmp) = app();

    for path in ["/", "/bots", "/sites", "/dynamic", "/help"] {
        let response = app.clone().oneshot(get(path)).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "{path} must not render to a stranger"
        );
        assert_eq!(
            response.headers()[header::LOCATION],
            "/login",
            "{path} should redirect to the login page"
        );
    }
}

#[tokio::test]
async fn the_login_page_and_its_assets_are_reachable_without_a_session() {
    let (app, _password, _tmp) = app();

    for path in ["/login", "/assets/style.css", "/assets/htmx.min.js"] {
        let response = app.clone().oneshot(get(path)).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{path} has to load before anyone can log in"
        );
    }
}

#[tokio::test]
async fn a_wrong_password_is_refused_and_sets_no_cookie() {
    let (app, _password, _tmp) = app();

    let response = app
        .clone()
        .oneshot(post("/login", "password=not-the-password"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        response.headers().get(header::SET_COOKIE).is_none(),
        "a failed login must not hand out a session"
    );
}

#[tokio::test]
async fn a_correct_password_opens_a_session_that_reaches_every_screen() {
    let (app, password, _tmp) = app();
    let (cookie, _csrf) = login(&app, &password).await;

    for path in ["/", "/bots", "/sites", "/dynamic", "/help"] {
        let response = app
            .clone()
            .oneshot(with_cookie(get(path), &cookie))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path} should render");
    }
}

#[tokio::test]
async fn a_forged_session_cookie_does_not_work() {
    let (app, _password, _tmp) = app();

    let response = app
        .clone()
        .oneshot(with_cookie(get("/"), "stop_bots_session=made-up"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/login");
}

#[tokio::test]
async fn logging_out_ends_the_session_server_side() {
    let (app, password, _tmp) = app();
    let (cookie, _csrf) = login(&app, &password).await;

    app.clone()
        .oneshot(with_cookie(post("/logout", ""), &cookie))
        .await
        .unwrap();

    // The same cookie must now be worthless — clearing it in the browser
    // is not what makes logout safe.
    let response = app
        .clone()
        .oneshot(with_cookie(get("/"), &cookie))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "a logged-out cookie must not still open the app"
    );
}

// ---- DNS rebinding ----

#[tokio::test]
async fn a_request_carrying_an_unlisted_host_is_refused() {
    let (app, _password, _tmp) = app();

    let request = Request::builder()
        .uri("/login")
        .header(header::HOST, "evil.example")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::MISDIRECTED_REQUEST,
        "this is the DNS-rebinding guard; a rebound request arrives under the attacker's name"
    );
}

#[tokio::test]
async fn loopback_host_names_are_accepted_without_configuration() {
    let (app, _password, _tmp) = app();

    for host in [
        "localhost",
        "localhost:8787",
        "127.0.0.1:8787",
        "[::1]:8787",
    ] {
        let request = Request::builder()
            .uri("/login")
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "Host: {host}");
    }
}

#[tokio::test]
async fn a_configured_host_becomes_acceptable() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(tmp.path().join("db.sqlite3")).unwrap();
    db.set_text_setting(stop_bots::web::ALLOWED_HOSTS_KEY, "admin.example.com")
        .unwrap();
    let state = AppState::new(db, tmp.path().join("nginx"), None, false);
    let app = server::router(state);

    let request = Request::builder()
        .uri("/login")
        .header(header::HOST, "admin.example.com")
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::OK);
}

// ---- CSRF ----

#[tokio::test]
async fn a_post_without_a_csrf_token_is_refused() {
    let (app, password, _tmp) = app();
    let (cookie, _csrf) = login(&app, &password).await;

    let response = app
        .clone()
        .oneshot(with_cookie(
            post("/dynamic/block-address", "address=192.0.2.1"),
            &cookie,
        ))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a session cookie alone must not be enough to change anything"
    );
}

#[tokio::test]
async fn a_post_with_another_sessions_csrf_token_is_refused() {
    let (app, password, _tmp) = app();
    let (first_cookie, _first_csrf) = login(&app, &password).await;
    let (_second_cookie, second_csrf) = login(&app, &password).await;

    let response = app
        .clone()
        .oneshot(with_cookie(
            post(
                "/dynamic/block-address",
                &format!("csrf={second_csrf}&address=192.0.2.1"),
            ),
            &first_cookie,
        ))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "tokens are per-session, so one session's token must not authorise another's request"
    );
}

#[tokio::test]
async fn a_post_with_the_right_csrf_token_is_accepted() {
    let (app, password, _tmp) = app();
    let (cookie, csrf) = login(&app, &password).await;

    let response = app
        .clone()
        .oneshot(with_cookie(
            post(
                "/dynamic/block-address",
                &format!("csrf={csrf}&address=192.0.2.1"),
            ),
            &cookie,
        ))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "an action redirects back to the page it came from"
    );
}

// ---- headers ----

#[tokio::test]
async fn every_response_carries_the_headers_that_lock_the_page_down() {
    let (app, _password, _tmp) = app();

    // Including a 404: an error page is as framable as any other if the
    // headers only go on the successful paths.
    for path in ["/login", "/no-such-page"] {
        let response = app.clone().oneshot(get(path)).await.unwrap();
        let headers = response.headers();

        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(
            csp.contains("frame-ancestors 'none'"),
            "a console that rewrites firewall rules must not be framable; {path} CSP was: {csp}"
        );
        assert!(csp.contains("default-src 'none'"), "{path} CSP was: {csp}");
        assert!(
            !csp.contains("unsafe-inline"),
            "{path} CSP must not allow inline script: {csp}"
        );
        assert_eq!(headers["x-frame-options"], "DENY", "{path}");
        assert_eq!(headers["x-content-type-options"], "nosniff", "{path}");
        assert_eq!(headers["referrer-policy"], "no-referrer", "{path}");
        assert_eq!(headers["cache-control"], "no-store", "{path}");
    }
}

#[tokio::test]
async fn the_csp_names_the_hash_of_the_one_inline_script() {
    let (app, _password, _tmp) = app();
    let response = app.oneshot(get("/login")).await.unwrap();
    let csp = response.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_string();

    let expected = stop_bots::web::layout::theme_script_hash();
    assert!(
        csp.contains(&expected),
        "the theme toggle is inline and must be allowed by hash, not by 'unsafe-inline'.\nCSP: {csp}\nexpected to contain: {expected}"
    );
}

#[tokio::test]
async fn the_session_cookie_is_not_readable_from_script() {
    let (app, password, _tmp) = app();

    let response = app
        .oneshot(post("/login", &format!("password={password}")))
        .await
        .unwrap();
    let set = response.headers()[header::SET_COOKIE].to_str().unwrap();

    assert!(set.contains("HttpOnly"), "was: {set}");
    assert!(
        set.contains("SameSite=Strict"),
        "SameSite is the second lock on CSRF; was: {set}"
    );
}

/// The CSP allows inline script only by hash, and a hash does not cover an
/// inline event handler — that needs `unsafe-hashes`, which is the hole
/// hashing was meant to avoid. So a page with an `onclick` is a page with
/// a control that silently does nothing in any browser that enforces CSP.
#[tokio::test]
async fn no_page_uses_an_inline_event_handler() {
    let (app, password, _tmp) = app();
    let (cookie, _csrf) = login(&app, &password).await;

    for path in ["/", "/bots", "/sites", "/dynamic", "/help"] {
        let response = app
            .clone()
            .oneshot(with_cookie(get(path), &cookie))
            .await
            .unwrap();
        let html = body_string(response).await;

        for handler in ["onclick=", "onchange=", "onsubmit=", "onload=", "onerror="] {
            assert!(
                !html.contains(handler),
                "{path} carries {handler}, which this server's own CSP blocks"
            );
        }
    }
}

/// The login page too — it is the one page an operator sees before
/// anything else works.
#[tokio::test]
async fn the_login_page_uses_no_inline_event_handler() {
    let (app, _password, _tmp) = app();
    let html = body_string(app.oneshot(get("/login")).await.unwrap()).await;
    assert!(!html.contains("onclick="), "was: {html}");
}
