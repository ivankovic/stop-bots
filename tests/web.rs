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
    let (router, password, tmp, _) = app_with_db();
    (router, password, tmp)
}

/// The same, keeping the database path so a test can open a second
/// connection and check what a handler actually wrote. SQLite is perfectly
/// happy with two connections to one file, and reading the result back
/// through the real database is what makes these tests assertions about
/// behaviour rather than about status codes.
fn app_with_db() -> (Router, String, tempfile::TempDir, std::path::PathBuf) {
    app_under("")
}

/// The same, served under a path prefix.
fn app_under(base: &str) -> (Router, String, tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db = Db::open(&db_path).unwrap();
    let password = stop_bots::web::auth::generate_password().unwrap();
    stop_bots::web::auth::set_password(&db, &password).unwrap();
    stop_bots::botlist::register_all_sources(&db).unwrap();
    stop_bots::ipranges::reputation::register_all_reputation_sources(&db).unwrap();
    drop(db);

    let nginx_root = tmp.path().join("nginx");
    std::fs::create_dir_all(nginx_root.join("sites-enabled")).unwrap();

    // `apply_for_real: false` throughout — a test must never reload the
    // developer's NGINX or run a firewall script at them.
    let state = AppState::with_base(
        Db::open(&db_path).unwrap(),
        nginx_root,
        None,
        false,
        stop_bots::web::BasePath::parse(base).unwrap(),
    );
    (server::router(state), password, tmp, db_path)
}

/// Posts a form with the session's CSRF token, and returns the flash
/// message the redirect carries.
///
/// The message is the handler's own account of what it did, so asserting
/// on it is asserting on the outcome the operator is shown — not on a
/// status code that a refusal and a success would share.
async fn act(
    app: &Router,
    cookie: &str,
    csrf: &str,
    path: &str,
    body: &str,
) -> (StatusCode, String) {
    let full = if body.is_empty() {
        format!("csrf={csrf}")
    } else {
        format!("csrf={csrf}&{body}")
    };
    let response = app
        .clone()
        .oneshot(with_cookie(post(path, &full), cookie))
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    // The flash rides in the query string; decode enough of it to read.
    let flash = location
        .split_once("flash=")
        .map(|(_, rest)| rest.split('&').next().unwrap_or_default().to_string())
        .map(|raw| percent_decode(&raw))
        .unwrap_or_default();
    (status, flash)
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap(), 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
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

// ---- actions: what the handlers actually write ----
//
// Every one of these reads the result back out of the database through a
// second connection, rather than trusting a 303. A refusal and a success
// are both redirects; the difference is what changed and what the operator
// is told.

use stop_bots::db::{BotStatus, Category, GeoMode, Policy};

#[tokio::test]
async fn setting_a_category_default_is_stored_and_reported() {
    let (app, password, _tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;

    let (status, flash) = act(
        &app,
        &cookie,
        &csrf,
        "/category",
        "category=ai&policy=allowed",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        flash.contains("AI bots"),
        "the message names the category: {flash}"
    );

    let db = Db::open(&db_path).unwrap();
    assert_eq!(
        db.get_category_default(Category::Ai).unwrap(),
        Policy::Allowed
    );
}

#[tokio::test]
async fn an_unknown_category_changes_nothing() {
    let (app, password, _tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;
    let before = Db::open(&db_path)
        .unwrap()
        .get_category_default(Category::Ai)
        .unwrap();

    let (_, flash) = act(
        &app,
        &cookie,
        &csrf,
        "/category",
        "category=wat&policy=allowed",
    )
    .await;
    assert!(flash.contains("not a category"), "was: {flash}");

    assert_eq!(
        Db::open(&db_path)
            .unwrap()
            .get_category_default(Category::Ai)
            .unwrap(),
        before
    );
}

#[tokio::test]
async fn the_geo_mode_and_country_selection_round_trip() {
    let (app, password, _tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;

    act(&app, &cookie, &csrf, "/geo-mode", "mode=allowlist").await;
    act(&app, &cookie, &csrf, "/geo-add", "country=cn").await;

    let db = Db::open(&db_path).unwrap();
    assert_eq!(db.get_geo_mode().unwrap(), GeoMode::Allowlist);
    assert_eq!(
        db.list_selected_countries().unwrap(),
        ["CN"],
        "a lowercase code is normalised, not rejected"
    );
    drop(db);

    act(&app, &cookie, &csrf, "/geo-remove", "country=CN").await;
    assert!(Db::open(&db_path)
        .unwrap()
        .list_selected_countries()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn a_country_that_is_not_a_two_letter_code_is_refused() {
    let (app, password, _tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;

    for bad in ["england", "c", "1"] {
        let (_, flash) = act(&app, &cookie, &csrf, "/geo-add", &format!("country={bad}")).await;
        assert!(flash.contains("two-letter"), "{bad} gave: {flash}");
    }
    assert!(Db::open(&db_path)
        .unwrap()
        .list_selected_countries()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn a_detector_can_be_switched_on_and_given_a_ttl() {
    use stop_bots::protection::Detector;

    let (app, password, _tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;
    let detector = Detector::ALL[0];

    act(
        &app,
        &cookie,
        &csrf,
        "/detector",
        &format!("detector={}&enabled=1", detector.id()),
    )
    .await;
    act(
        &app,
        &cookie,
        &csrf,
        "/detector-ttl",
        &format!("detector={}&days=9", detector.id()),
    )
    .await;

    let db = Db::open(&db_path).unwrap();
    assert!(detector.is_enabled(&db).unwrap());
    assert_eq!(detector.ttl_days(&db).unwrap(), 9);
}

#[tokio::test]
async fn a_zero_day_ttl_is_refused() {
    use stop_bots::protection::Detector;

    let (app, password, _tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;
    let detector = Detector::ALL[0];
    let before = detector.ttl_days(&Db::open(&db_path).unwrap()).unwrap();

    let (_, flash) = act(
        &app,
        &cookie,
        &csrf,
        "/detector-ttl",
        &format!("detector={}&days=0", detector.id()),
    )
    .await;
    assert!(flash.contains("at least a day"), "was: {flash}");
    assert_eq!(
        detector.ttl_days(&Db::open(&db_path).unwrap()).unwrap(),
        before
    );
}

#[tokio::test]
async fn a_reputation_feed_can_be_switched_on() {
    let (app, password, _tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;

    let id = Db::open(&db_path)
        .unwrap()
        .list_reputation_sources()
        .unwrap()[0]
        .id
        .clone();
    act(
        &app,
        &cookie,
        &csrf,
        "/feed",
        &format!("feed={id}&enabled=1"),
    )
    .await;

    let enabled = Db::open(&db_path)
        .unwrap()
        .list_reputation_sources()
        .unwrap()
        .into_iter()
        .find(|s| s.id == id)
        .unwrap()
        .enabled;
    assert!(enabled);
}

#[tokio::test]
async fn writing_the_firewall_script_produces_a_file_and_records_the_signature() {
    let (app, password, tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;

    Db::open(&db_path)
        .unwrap()
        .block_address_permanently("192.0.2.10")
        .unwrap();

    let out = tmp.path().join("firewall.sh");
    let (_, flash) = act(
        &app,
        &cookie,
        &csrf,
        "/render-firewall",
        &format!("out={}&backend=nftables", out.display()),
    )
    .await;

    assert!(flash.contains("Wrote"), "was: {flash}");
    let script = std::fs::read_to_string(&out).expect("the script must exist on disk");
    assert!(script.contains("192.0.2.10"), "script was:\n{script}");
    assert!(
        Db::open(&db_path)
            .unwrap()
            .get_firewall_rendered_signature()
            .unwrap()
            .is_some(),
        "recording the signature is what stops the Dashboard calling it stale straight away"
    );
}

#[tokio::test]
async fn writing_the_firewall_script_needs_somewhere_to_write_it() {
    let (app, password, _tmp, _db) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;

    let (_, flash) = act(
        &app,
        &cookie,
        &csrf,
        "/render-firewall",
        "out=&backend=nftables",
    )
    .await;
    assert!(flash.contains("path"), "was: {flash}");
}

#[tokio::test]
async fn a_bot_override_is_stored() {
    let (app, password, _tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;

    let db = Db::open(&db_path).unwrap();
    db.upsert_bot(&stop_bots::db::NewBot {
        slug: "gptbot".into(),
        name: "GPTBot".into(),
        is_ai: true,
        is_search_engine: false,
        is_scanner: false,
        user_agent_pattern: "gptbot".into(),
        source_id: "well-known-bots".into(),
    })
    .unwrap();
    drop(db);

    act(
        &app,
        &cookie,
        &csrf,
        "/bots/status",
        "slug=gptbot&status=blocked",
    )
    .await;

    let status = Db::open(&db_path)
        .unwrap()
        .list_bots()
        .unwrap()
        .into_iter()
        .find(|b| b.slug == "gptbot")
        .unwrap()
        .status;
    assert_eq!(status, BotStatus::Blocked);
}

// ---- sites ----

/// Writes a site config under the router's NGINX root and returns its path.
fn write_site(tmp: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
    let path = tmp.path().join("nginx/sites-enabled").join(name);
    std::fs::write(
        &path,
        format!("server {{\n    listen 80;\n    server_name {name};\n}}\n"),
    )
    .unwrap();
    path
}

#[tokio::test]
async fn scanning_finds_the_sites_on_disk() {
    let (app, password, tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;
    write_site(&tmp, "example.com");
    write_site(&tmp, "shop.example.com");

    let (_, flash) = act(&app, &cookie, &csrf, "/sites/scan", "").await;
    assert!(flash.contains("2 site"), "was: {flash}");

    let names: Vec<String> = Db::open(&db_path)
        .unwrap()
        .list_sites()
        .unwrap()
        .into_iter()
        .map(|s| s.server_name)
        .collect();
    assert!(names.contains(&"example.com".to_string()), "got: {names:?}");
}

#[tokio::test]
async fn the_nginx_settings_round_trip() {
    let (app, password, _tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;

    act(
        &app,
        &cookie,
        &csrf,
        "/sites/block-response",
        "response=444",
    )
    .await;
    act(&app, &cookie, &csrf, "/sites/robots", "enabled=1").await;
    act(
        &app,
        &cookie,
        &csrf,
        "/sites/rate-limit",
        "enabled=1&rps=7&burst=21",
    )
    .await;

    let db = Db::open(&db_path).unwrap();
    assert_eq!(db.get_block_response().unwrap().stored(), "444");
    assert!(db.get_serve_robots_txt().unwrap());
    assert!(db.get_rate_limit_enabled().unwrap());
    assert_eq!(db.get_rate_limit_rps().unwrap(), 7);
    assert_eq!(db.get_rate_limit_burst().unwrap(), 21);
}

#[tokio::test]
async fn a_rate_limit_of_zero_is_refused() {
    let (app, password, _tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;

    let (_, flash) = act(
        &app,
        &cookie,
        &csrf,
        "/sites/rate-limit",
        "enabled=1&rps=0&burst=5",
    )
    .await;
    assert!(flash.contains("at least 1"), "was: {flash}");
    assert!(
        !Db::open(&db_path)
            .unwrap()
            .get_rate_limit_enabled()
            .unwrap(),
        "a refused save must not switch it on"
    );
}

#[tokio::test]
async fn applying_writes_the_rule_into_the_site_config() {
    let (app, password, tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;
    let path = write_site(&tmp, "example.com");

    // Something to block, or an apply writes nothing.
    let db = Db::open(&db_path).unwrap();
    db.upsert_bot(&stop_bots::db::NewBot {
        slug: "gptbot".into(),
        name: "GPTBot".into(),
        is_ai: true,
        is_search_engine: false,
        is_scanner: false,
        user_agent_pattern: "GPTBot".into(),
        source_id: "well-known-bots".into(),
    })
    .unwrap();
    db.set_bot_status("gptbot", BotStatus::Blocked).unwrap();
    drop(db);

    act(&app, &cookie, &csrf, "/sites/scan", "").await;
    let id = Db::open(&db_path).unwrap().list_sites().unwrap()[0].id;
    let (_, flash) = act(&app, &cookie, &csrf, "/sites/apply", &format!("id={id}")).await;

    assert!(flash.contains("Applied"), "was: {flash}");
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(
        written.contains("GPTBot"),
        "the blocking rule should be in the config now:\n{written}"
    );
    assert!(
        flash.contains("--no-apply"),
        "the message must say NGINX was not reloaded: {flash}"
    );
}

#[tokio::test]
async fn applying_to_every_site_touches_all_of_them() {
    let (app, password, tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;
    let first = write_site(&tmp, "a.example");
    let second = write_site(&tmp, "b.example");

    let db = Db::open(&db_path).unwrap();
    db.upsert_bot(&stop_bots::db::NewBot {
        slug: "gptbot".into(),
        name: "GPTBot".into(),
        is_ai: true,
        is_search_engine: false,
        is_scanner: false,
        user_agent_pattern: "GPTBot".into(),
        source_id: "well-known-bots".into(),
    })
    .unwrap();
    db.set_bot_status("gptbot", BotStatus::Blocked).unwrap();
    drop(db);

    act(&app, &cookie, &csrf, "/sites/scan", "").await;
    act(&app, &cookie, &csrf, "/sites/apply-all", "").await;

    for path in [first, second] {
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("GPTBot"),
            "{} was:\n{written}",
            path.display()
        );
    }
}

#[tokio::test]
async fn a_site_detail_page_renders_and_its_overrides_stick() {
    let (app, password, tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;
    write_site(&tmp, "example.com");
    act(&app, &cookie, &csrf, "/sites/scan", "").await;
    let id = Db::open(&db_path).unwrap().list_sites().unwrap()[0].id;

    let page = app
        .clone()
        .oneshot(with_cookie(get(&format!("/sites/{id}")), &cookie))
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert!(body_string(page).await.contains("example.com"));

    act(
        &app,
        &cookie,
        &csrf,
        &format!("/sites/{id}/category"),
        "category=ai&policy=blocked",
    )
    .await;
    act(
        &app,
        &cookie,
        &csrf,
        &format!("/sites/{id}/exempt-add"),
        "path=/blog",
    )
    .await;

    let db = Db::open(&db_path).unwrap();
    assert_eq!(
        db.get_site_category_override(id, Category::Ai).unwrap(),
        Some(Policy::Blocked)
    );
    assert_eq!(db.site_path_exemptions(id).unwrap(), ["/blog"]);
    drop(db);

    act(
        &app,
        &cookie,
        &csrf,
        &format!("/sites/{id}/exempt-remove"),
        "path=/blog",
    )
    .await;
    assert!(Db::open(&db_path)
        .unwrap()
        .site_path_exemptions(id)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn an_exemption_that_is_not_a_path_is_refused() {
    let (app, password, tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;
    write_site(&tmp, "example.com");
    act(&app, &cookie, &csrf, "/sites/scan", "").await;
    let id = Db::open(&db_path).unwrap().list_sites().unwrap()[0].id;

    let (_, flash) = act(
        &app,
        &cookie,
        &csrf,
        &format!("/sites/{id}/exempt-add"),
        "path=blog",
    )
    .await;
    assert!(flash.contains("start with"), "was: {flash}");
    assert!(Db::open(&db_path)
        .unwrap()
        .site_path_exemptions(id)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn a_request_shape_rule_can_be_switched_on_for_one_site() {
    let (app, password, tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;
    write_site(&tmp, "example.com");
    act(&app, &cookie, &csrf, "/sites/scan", "").await;
    let id = Db::open(&db_path).unwrap().list_sites().unwrap()[0].id;

    let rule = stop_bots::nginx::RequestRule::ALL[1];
    act(
        &app,
        &cookie,
        &csrf,
        &format!("/sites/{id}/rule"),
        &format!("rule={}&enabled=1", rule.id()),
    )
    .await;

    assert_eq!(
        Db::open(&db_path).unwrap().site_request_rules(id).unwrap(),
        [rule.id()]
    );
}

// ---- dynamic protection ----

#[tokio::test]
async fn blocking_and_unblocking_an_address_round_trips() {
    let (app, password, _tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;

    act(
        &app,
        &cookie,
        &csrf,
        "/dynamic/block-address",
        "address=192.0.2.55",
    )
    .await;
    assert!(
        Db::open(&db_path)
            .unwrap()
            .list_firewall_rules()
            .unwrap()
            .iter()
            .any(|r| r.address == "192.0.2.55"),
        "the rule should be stored"
    );

    act(
        &app,
        &cookie,
        &csrf,
        "/dynamic/unblock-address",
        "address=192.0.2.55",
    )
    .await;
    assert!(Db::open(&db_path)
        .unwrap()
        .list_firewall_rules()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn blocking_and_unblocking_a_user_agent_round_trips() {
    let (app, password, _tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;

    act(
        &app,
        &cookie,
        &csrf,
        "/dynamic/block-ua",
        "user_agent=curl%2F8.5.0",
    )
    .await;
    assert_eq!(
        Db::open(&db_path)
            .unwrap()
            .list_blocked_user_agents()
            .unwrap(),
        ["curl/8.5.0"]
    );

    act(
        &app,
        &cookie,
        &csrf,
        "/dynamic/unblock-ua",
        "user_agent=curl%2F8.5.0",
    )
    .await;
    assert!(Db::open(&db_path)
        .unwrap()
        .list_blocked_user_agents()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn the_dynamic_screen_filters_are_all_reachable() {
    let (app, password, _tmp, _db) = app_with_db();
    let (cookie, _csrf) = login(&app, &password).await;

    for filter in ["all", "pending", "blocked", "nonsense"] {
        let response = app
            .clone()
            .oneshot(with_cookie(
                get(&format!("/dynamic?filter={filter}")),
                &cookie,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "filter={filter}");
    }
}

#[tokio::test]
async fn searching_the_bot_list_is_reachable_from_the_url() {
    let (app, password, _tmp, _db) = app_with_db();
    let (cookie, _csrf) = login(&app, &password).await;

    let response = app
        .oneshot(with_cookie(get("/bots?q=gpt"), &cookie))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// The anti-lockout guard, through the router.
///
/// `ConnectInfo` is normally supplied by the listener, which these tests do
/// not use — so it is inserted into the request's extensions directly,
/// which is exactly where the middleware reads it from. That keeps the
/// guard under test rather than the plumbing that feeds it.
fn from_peer(mut request: Request<Body>, peer: &str) -> Request<Body> {
    let addr: std::net::SocketAddr = peer.parse().unwrap();
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(addr));
    request
}

#[tokio::test]
async fn blocking_the_address_you_are_connected_from_is_refused() {
    let (app, password, _tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;

    let request = from_peer(
        with_cookie(
            post(
                "/dynamic/block-address",
                &format!("csrf={csrf}&address=203.0.113.5"),
            ),
            &cookie,
        ),
        "203.0.113.5:44321",
    );
    let response = app.clone().oneshot(request).await.unwrap();
    let location = response.headers()[header::LOCATION].to_str().unwrap();

    assert!(
        percent_decode(location).contains("lock you out"),
        "location was: {location}"
    );
    assert!(
        Db::open(&db_path)
            .unwrap()
            .list_firewall_rules()
            .unwrap()
            .is_empty(),
        "the refusal has to actually prevent the write, not just word it differently"
    );
}

#[tokio::test]
async fn blocking_a_different_address_from_the_same_peer_still_works() {
    let (app, password, _tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;

    let request = from_peer(
        with_cookie(
            post(
                "/dynamic/block-address",
                &format!("csrf={csrf}&address=198.51.100.9"),
            ),
            &cookie,
        ),
        "203.0.113.5:44321",
    );
    app.clone().oneshot(request).await.unwrap();

    assert_eq!(
        Db::open(&db_path)
            .unwrap()
            .list_firewall_rules()
            .unwrap()
            .len(),
        1,
        "the guard must only refuse the caller's own address"
    );
}

/// With a proxy in front, the peer is the proxy. The guard follows
/// `X-Forwarded-For` — but only once the operator has said a proxy exists,
/// because otherwise the header is just text anyone can send.
#[tokio::test]
async fn a_forwarded_address_is_only_believed_when_configured() {
    let (app, password, _tmp, db_path) = app_with_db();
    let (cookie, csrf) = login(&app, &password).await;

    let attempt = |app: Router, cookie: String, csrf: String| async move {
        let mut request = from_peer(
            with_cookie(
                post(
                    "/dynamic/block-address",
                    &format!("csrf={csrf}&address=203.0.113.77"),
                ),
                &cookie,
            ),
            "127.0.0.1:5000",
        );
        request
            .headers_mut()
            .insert("x-forwarded-for", "203.0.113.77".parse().unwrap());
        let response = app.oneshot(request).await.unwrap();
        percent_decode(response.headers()[header::LOCATION].to_str().unwrap())
    };

    // Untrusted: the header is ignored, so the block goes through.
    let flash = attempt(app.clone(), cookie.clone(), csrf.clone()).await;
    assert!(
        flash.contains("Blocked"),
        "an untrusted forwarded header must not be able to veto a block: {flash}"
    );

    let db = Db::open(&db_path).unwrap();
    db.unblock_address("203.0.113.77").unwrap();
    db.set_bool_setting(stop_bots::web::TRUST_FORWARDED_KEY, true)
        .unwrap();
    drop(db);

    // Trusted: now it names the client, and the guard fires.
    let flash = attempt(app, cookie, csrf).await;
    assert!(flash.contains("lock you out"), "was: {flash}");
    assert!(Db::open(&db_path)
        .unwrap()
        .list_firewall_rules()
        .unwrap()
        .is_empty());
}

// ---- served under a path prefix ----
//
// The whole point of `--base-path` is that *nothing* the browser is told
// to fetch escapes the prefix. A single absolute `/bots` left in a
// template is a broken link that only shows up in a proxied deployment,
// so the check here is exhaustive over the emitted markup rather than a
// spot check on a few known URLs.

const PREFIX: &str = "/stop-bots";

fn get_under(path: &str) -> Request<Body> {
    get(&format!("{PREFIX}{path}"))
}

/// Every URL the page emits, from `href`, `src` and `action` attributes.
fn emitted_urls(html: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for attribute in ["href=\"", "src=\"", "action=\""] {
        for (_, rest) in html
            .match_indices(attribute)
            .map(|(i, _)| (i, &html[i + attribute.len()..]))
        {
            if let Some(url) = rest.split('"').next() {
                urls.push(url.to_string());
            }
        }
    }
    urls
}

#[tokio::test]
async fn under_a_prefix_the_screens_are_reachable_at_the_prefixed_paths() {
    let (app, password, _tmp, _db) = app_under(PREFIX);

    // Login first, at the prefixed path.
    let response = app
        .clone()
        .oneshot(post(
            &format!("{PREFIX}/login"),
            &format!("password={password}"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[header::LOCATION],
        "/stop-bots/",
        "the post-login redirect must land inside the prefix, with its trailing slash"
    );
    let cookie = session_cookie_from(&response);

    for path in ["/", "/bots", "/sites", "/dynamic", "/help"] {
        let response = app
            .clone()
            .oneshot(with_cookie(get_under(path), &cookie))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{PREFIX}{path} should render"
        );
    }
}

#[tokio::test]
async fn under_a_prefix_the_unprefixed_paths_are_not_served() {
    let (app, _password, _tmp, _db) = app_under(PREFIX);

    // This is what makes the "proxy must not strip the prefix" rule
    // enforceable rather than advice: a stripped request does not
    // accidentally half-work.
    for path in ["/login", "/", "/assets/style.css"] {
        let response = app.clone().oneshot(get(path)).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{path} must not be served when a prefix is configured"
        );
    }
}

#[tokio::test]
async fn no_url_on_any_page_escapes_the_prefix() {
    let (app, password, tmp, db_path) = app_under(PREFIX);

    // Seed enough that every table renders rows, so their action URLs are
    // in the markup being checked rather than behind an empty state.
    let db = Db::open(&db_path).unwrap();
    db.upsert_bot(&stop_bots::db::NewBot {
        slug: "gptbot".into(),
        name: "GPTBot".into(),
        is_ai: true,
        is_search_engine: false,
        is_scanner: false,
        user_agent_pattern: "GPTBot".into(),
        source_id: "well-known-bots".into(),
    })
    .unwrap();
    db.block_address_permanently("192.0.2.9").unwrap();
    db.set_country_selected("CN", true).unwrap();
    drop(db);
    write_site(&tmp, "example.com");

    let response = app
        .clone()
        .oneshot(post(
            &format!("{PREFIX}/login"),
            &format!("password={password}"),
        ))
        .await
        .unwrap();
    let cookie = session_cookie_from(&response);

    let csrf_page = app
        .clone()
        .oneshot(with_cookie(get_under("/sites"), &cookie))
        .await
        .unwrap();
    let csrf = body_string(csrf_page)
        .await
        .split(r#"<meta name="csrf-token" content=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap()
        .to_string();

    let scan = format!("{PREFIX}/sites/scan");
    app.clone()
        .oneshot(with_cookie(post(&scan, &format!("csrf={csrf}")), &cookie))
        .await
        .unwrap();
    let site_id = Db::open(&db_path).unwrap().list_sites().unwrap()[0].id;

    let pages = [
        "/".to_string(),
        "/bots".to_string(),
        "/bots?q=gpt".to_string(),
        "/sites".to_string(),
        format!("/sites/{site_id}"),
        "/dynamic".to_string(),
        "/help".to_string(),
    ];

    for path in pages {
        let response = app
            .clone()
            .oneshot(with_cookie(get_under(&path), &cookie))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let html = body_string(response).await;

        let urls = emitted_urls(&html);
        assert!(!urls.is_empty(), "{path} emitted no URLs at all to check");

        for url in urls {
            // Off-site links (the README's, say) and fragments are none of
            // this check's business; a root-relative one is.
            if !url.starts_with('/') {
                continue;
            }
            assert!(
                url.starts_with("/stop-bots/"),
                "{path} emits {url}, which points outside the prefix and would 404 behind the proxy"
            );
        }
    }
}

#[tokio::test]
async fn under_a_prefix_the_session_cookie_is_scoped_to_it() {
    let (app, password, _tmp, _db) = app_under(PREFIX);

    let response = app
        .oneshot(post(
            &format!("{PREFIX}/login"),
            &format!("password={password}"),
        ))
        .await
        .unwrap();
    let set = response.headers()[header::SET_COOKIE].to_str().unwrap();

    assert!(
        set.contains("Path=/stop-bots/"),
        "a session for this console has no business being sent to every other app on the \
         domain; was: {set}"
    );
}

#[tokio::test]
async fn under_a_prefix_a_redirect_after_an_action_stays_inside_it() {
    let (app, password, _tmp, _db) = app_under(PREFIX);
    let response = app
        .clone()
        .oneshot(post(
            &format!("{PREFIX}/login"),
            &format!("password={password}"),
        ))
        .await
        .unwrap();
    let cookie = session_cookie_from(&response);

    let page = app
        .clone()
        .oneshot(with_cookie(get_under("/"), &cookie))
        .await
        .unwrap();
    let csrf = body_string(page)
        .await
        .split(r#"<meta name="csrf-token" content=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap()
        .to_string();

    let response = app
        .oneshot(with_cookie(
            post(
                &format!("{PREFIX}/category"),
                &format!("csrf={csrf}&category=ai&policy=allowed"),
            ),
            &cookie,
        ))
        .await
        .unwrap();
    let location = response.headers()[header::LOCATION].to_str().unwrap();
    assert!(
        location.starts_with("/stop-bots/?flash="),
        "an action's redirect must come back inside the prefix; was: {location}"
    );
}

#[tokio::test]
async fn an_unauthenticated_request_under_a_prefix_is_sent_to_the_prefixed_login() {
    let (app, _password, _tmp, _db) = app_under(PREFIX);

    let response = app.oneshot(get_under("/bots")).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[header::LOCATION],
        "/stop-bots/login",
        "redirecting to /login would send the browser outside the location block"
    );
}
