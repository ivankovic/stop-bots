// SPDX-License-Identifier: AGPL-3.0-or-later
//! The one place this project makes an outbound request.
//!
//! Every bot list and IP-range feed is fetched from a third party, and
//! `SECURITY.md` puts a hostile upstream explicitly in scope. Each call site
//! used to be a bare `reqwest::get(url).text()`, which has no connect
//! timeout, no total timeout and no bound on how much it will read into
//! memory. Two of the three matter most under the internal cron, where the
//! fetch happens with nobody watching: a peer that accepts the connection
//! and then says nothing stalls that job forever, and a body large enough
//! to exhaust memory takes the whole console with it.
//!
//! Centralising also means one `Client`, so the connection pool and the TLS
//! setup are built once rather than per call.

use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result};

/// How long a whole fetch may take, connect through last byte.
///
/// Generous on purpose. `us-aggregated.zone` is ~29,000 lines and FireHOL's
/// level 1 netset is comparable, so this is not a latency budget — it is
/// the point past which a peer is assumed never to finish.
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// How long the connection itself may take to establish. Separate from
/// [`TIMEOUT`] so a host that is simply unreachable fails quickly instead
/// of holding a cron job for a minute.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest response body accepted, in bytes.
///
/// Well above anything these feeds legitimately serve — the largest by an
/// order of magnitude is an aggregated country zone file, around 500KB —
/// and well below what would trouble a host running NGINX. A body that
/// exceeds this is refused rather than truncated: a truncated blocklist is
/// a blocklist with entries silently missing, which is worse than not
/// updating at all.
pub const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .user_agent(concat!("stop-bots/", env!("CARGO_PKG_VERSION")))
            // A redirect is normal for these feeds (several are served from
            // a CDN), but an unbounded chain is a way to keep a connection
            // open indefinitely without ever exceeding a per-request limit.
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            // Only fails if the TLS backend cannot be initialised, which is
            // a broken build rather than a runtime condition.
            .unwrap_or_default()
    })
}

/// Fetches `url` as text, with [`TIMEOUT`] and [`MAX_BODY_BYTES`] applied.
///
/// `what` names the source for error messages — "GPTBot IP ranges", not the
/// URL, because that is what the admin recognises in a cron log.
pub async fn text(url: &str, what: &str) -> Result<String> {
    capped_text(url, what, MAX_BODY_BYTES).await
}

/// [`text`] with the limit as a parameter, so the refusal paths can be
/// tested against a few bytes rather than by actually serving 32MB.
async fn capped_text(url: &str, what: &str, max_bytes: usize) -> Result<String> {
    let response = client()
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to fetch {what}"))?
        .error_for_status()
        .with_context(|| format!("{what} request failed"))?;

    // The declared length first, so an oversized body is refused before a
    // single byte of it is read. Advisory only — nothing obliges a peer to
    // send it, or to send a true one — which is why the loop below still
    // counts.
    if let Some(len) = response.content_length() {
        if len > max_bytes as u64 {
            anyhow::bail!("{what} response is {len} bytes, over the {max_bytes}-byte limit");
        }
    }

    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("failed to read {what} response body"))?
    {
        if body.len() + chunk.len() > max_bytes {
            anyhow::bail!("{what} response exceeded the {max_bytes}-byte limit");
        }
        body.extend_from_slice(&chunk);
    }

    String::from_utf8(body).with_context(|| format!("{what} response was not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serves one canned response on a loopback port and returns its URL.
    ///
    /// A real server rather than a mocked client: the thing under test is
    /// how this code behaves against bytes on a socket, and a fake
    /// `reqwest` would test the fake. `Connection: close` with no
    /// `Content-Length` is how a body of undeclared length arrives, which
    /// is the case the counting loop exists for.
    fn serve(response: &'static [u8]) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/list", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut discard = [0u8; 1024];
            let _ = stream.read(&mut discard);
            let _ = stream.write_all(response);
        });
        url
    }

    #[tokio::test]
    async fn a_body_within_the_limit_comes_back_as_text() {
        let url = serve(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n1.2.3.4\n");

        assert_eq!(capped_text(&url, "a feed", 64).await.unwrap(), "1.2.3.4\n");
    }

    /// The declared length is checked first so an oversized body is refused
    /// before a byte of it is read.
    #[tokio::test]
    async fn a_declared_length_over_the_limit_is_refused() {
        let url = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 9999\r\n\r\nxxxx");

        let err = capped_text(&url, "a feed", 8).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("9999 bytes, over the 8-byte limit"),
            "was: {err:#}"
        );
    }

    /// Nothing obliges a peer to declare a length, or to declare a true
    /// one, so the bytes are counted as they arrive as well.
    #[tokio::test]
    async fn an_undeclared_body_over_the_limit_is_refused_while_reading() {
        let url = serve(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nfar too many bytes for this");

        let err = capped_text(&url, "a feed", 8).await.unwrap_err();
        assert!(
            err.to_string().contains("exceeded the 8-byte limit"),
            "was: {err:#}"
        );
    }

    /// The error names the source, not the URL: a cron log is read by
    /// someone who recognises "the ai.robots.txt list".
    #[tokio::test]
    async fn a_failing_status_is_reported_against_the_source_name() {
        let url = serve(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n");

        let err = capped_text(&url, "the ai.robots.txt list", 64)
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("the ai.robots.txt list request failed"),
            "was: {err:#}"
        );
    }
    /// The six call sites now share one `Client`, where each used to build
    /// its own. Bailing on an over-cap response drops the `Response`
    /// mid-body, so this checks that doing so leaves the shared connection
    /// pool able to serve the next fetch.
    #[tokio::test]
    async fn a_refused_fetch_does_not_spoil_the_shared_client() {
        let big = serve(
            b"HTTP/1.1 200 OK\r\nContent-Length: 9999\r\nConnection: close\r\n\r\nxxxxxxxxxxxxxxxx",
        );
        assert!(capped_text(&big, "a feed", 8).await.is_err());

        let good = serve(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n1.2.3.4\n");
        assert_eq!(capped_text(&good, "a feed", 64).await.unwrap(), "1.2.3.4\n");
    }
}
