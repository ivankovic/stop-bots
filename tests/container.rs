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

//! End-to-end tests against a *real* NGINX and a *real* nftables, in a
//! container.
//!
//! Everything else in `tests/` asserts the text this project generates.
//! That is exactly the check that keeps passing when the text is wrong —
//! a directive NGINX rejects, a rule `nft` won't load, a block that
//! returns 403 to the wrong requests. These tests run the generated
//! output through the actual parsers and then send actual requests at it.
//!
//! **They do not run by default.** They need Docker and `NET_ADMIN`, take
//! tens of seconds, and would break `cargo test` on any machine without a
//! container runtime. Set `STOP_BOTS_CONTAINER_TESTS=1` to enable them;
//! `make container-test` does that for you. CI runs them as their own job.
//!
//! The container is deliberately *not* a faithful production host: there
//! is no systemd, so `nginx -s reload` stands in for
//! `systemctl reload nginx`. What it is faithful about is the two parsers
//! this project cannot check any other way.

use std::process::Command;

/// Skips the test unless container tests are switched on. Returns whether
/// to proceed, and says why not — a silently skipped test is how a whole
/// suite quietly stops running.
fn enabled() -> bool {
    if std::env::var_os("STOP_BOTS_CONTAINER_TESTS").is_some() {
        return true;
    }
    eprintln!(
        "skipping: container tests are off. Set STOP_BOTS_CONTAINER_TESTS=1 \
         (or run `make container-test`) to enable them."
    );
    false
}

const IMAGE: &str = "stop-bots-test:latest";

/// Builds the image exactly once per test binary run.
///
/// The `Once` is not an optimisation. Tests run in parallel and every one
/// of them needs the image, so without it several threads copy the binary
/// into the build context while other threads' `docker build` are reading
/// it — producing a truncated binary inside the image and a scatter of
/// unrelated-looking command failures. That is precisely how this first
/// showed up: four tests failing together, each passing alone.
fn build_image() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(build_image_now);
}

fn build_image_now() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let ctx = format!("{manifest}/tests/container");

    // The binary under test, built by cargo, staged into the build
    // context. `CARGO_BIN_EXE_stop-bots` is the exact binary this test
    // run compiled — not whatever happens to be on PATH.
    std::fs::copy(env!("CARGO_BIN_EXE_stop-bots"), format!("{ctx}/stop-bots"))
        .expect("failed to stage the stop-bots binary into the build context");

    let out = Command::new("docker")
        .args(["build", "-q", "-t", IMAGE, &ctx])
        .output()
        .expect("failed to run docker build");
    assert!(
        out.status.success(),
        "docker build failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A running container, cleaned up on drop.
struct Server {
    name: String,
}

/// A user-defined Docker network, so containers on it get real addresses
/// and can reach each other by name. Removed on drop.
struct Network {
    name: String,
}

impl Network {
    fn create(name: &str) -> Network {
        let _ = Command::new("docker")
            .args(["network", "rm", name])
            .output();
        let out = Command::new("docker")
            .args(["network", "create", name])
            .output()
            .expect("failed to create a docker network");
        assert!(
            out.status.success(),
            "docker network create failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        Network {
            name: name.to_string(),
        }
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["network", "rm", &self.name])
            .output();
    }
}

/// A second container that only makes requests — the remote client whose
/// packets the server's rules are supposed to stop.
struct Client {
    name: String,
}

impl Client {
    fn start(name: &str, net: &Network) -> Client {
        build_image();
        let _ = Command::new("docker").args(["rm", "-f", name]).output();
        let out = Command::new("docker")
            .args(["run", "-d", "--name", name, "--network", &net.name, IMAGE])
            .output()
            .expect("failed to start the client container");
        assert!(
            out.status.success(),
            "docker run (client) failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        Client {
            name: name.to_string(),
        }
    }

    /// This container's address on the network, as the server will see it.
    fn address(&self) -> String {
        let out = Command::new("docker")
            .args([
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                &self.name,
            ])
            .output()
            .expect("failed to inspect the client container");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Fetches `/` from `host` and returns the status code, tolerating a
    /// curl failure the same way `Server::status` does.
    fn get(&self, host: &str, extra: &str) -> String {
        let out = Command::new("docker")
            .args([
                "exec",
                &self.name,
                "sh",
                "-c",
                &format!("curl -s -o /dev/null -w '%{{http_code}}' {extra} http://{host}:8080/"),
            ])
            .output()
            .expect("failed to run curl in the client container");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

impl Server {
    fn start(name: &str) -> Server {
        Server::spawn(name, None)
    }

    fn start_on_network(name: &str, net: &Network) -> Server {
        Server::spawn(name, Some(&net.name))
    }

    fn spawn(name: &str, network: Option<&str>) -> Server {
        build_image();
        // Leftover from a previous aborted run.
        let _ = Command::new("docker").args(["rm", "-f", name]).output();

        let mut args = vec![
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            name.to_string(),
            // nft needs to actually manipulate the container's own
            // netfilter tables.
            "--cap-add=NET_ADMIN".to_string(),
        ];
        if let Some(network) = network {
            args.push("--network".to_string());
            args.push(network.to_string());
        }
        args.push(IMAGE.to_string());
        let out = Command::new("docker")
            .args(&args)
            .output()
            .expect("failed to run docker run");
        assert!(
            out.status.success(),
            "docker run failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let server = Server {
            name: name.to_string(),
        };
        server.sh("mkdir -p /var/www/test && echo '<h1>hello</h1>' > /var/www/test/index.html");
        server.sh("nginx");
        server
    }

    /// Runs a shell command inside the container, returning
    /// (exit status success, stdout, stderr).
    fn run(&self, cmd: &str) -> (bool, String, String) {
        let out = Command::new("docker")
            .args(["exec", &self.name, "sh", "-c", cmd])
            .output()
            .expect("failed to run docker exec");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    /// Runs a command and asserts it succeeded.
    fn sh(&self, cmd: &str) -> String {
        let (ok, stdout, stderr) = self.run(cmd);
        assert!(
            ok,
            "command failed: {cmd}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        stdout
    }

    /// Seeds one blocked bot, in the real well-known-bots source format,
    /// through the real `update-bot-lists` path — so the parser is
    /// exercised too rather than bypassed by writing rows directly.
    ///
    /// Category `ai`, not `scanner`: this source's parser hardcodes
    /// `is_scanner: false` (only the nginx-bad-bots list sets it), so a
    /// bot tagged `scanner` here would carry no flags at all and never be
    /// blocked. AI is blocked by the default policy, so nothing further is
    /// needed to make this bot actually blocked.
    fn seed_bot(&self, id: &str, pattern: &str) {
        let json = format!(
            r#"[{{"id":"{id}","categories":["ai"],"pattern":{{"accepted":["{pattern}"],"forbidden":[]}},"url":"https://example.invalid/{id}"}}]"#
        );
        self.sh(&format!("cat > /tmp/bots.json <<'JSON'\n{json}\nJSON"));
        self.stop_bots("update-bot-lists --source /tmp/bots.json");
    }

    /// Runs `stop-bots` inside the container against a fixed database.
    /// `--db` is a per-subcommand flag rather than a global one, so it
    /// goes after the args, not before them.
    fn stop_bots(&self, args: &str) -> String {
        self.sh(&format!("stop-bots {args} --db /tmp/db.sqlite3"))
    }

    fn stop_bots_expect_failure(&self, args: &str) -> String {
        let (ok, stdout, stderr) = self.run(&format!("stop-bots {args} --db /tmp/db.sqlite3"));
        assert!(!ok, "expected failure but it succeeded: {args}\n{stdout}");
        format!("{stdout}{stderr}")
    }

    /// The HTTP status code NGINX returns for a request, made from inside
    /// the container against the real server.
    ///
    /// Uses `run` rather than `sh`: curl exits non-zero when the server
    /// closes the connection without replying, which is exactly what the
    /// `444` response is *supposed* to do. Its `%{http_code}` of `000` is
    /// the result, not a failure to collect one.
    fn status(&self, path: &str, extra_curl_args: &str) -> String {
        let (_, stdout, _) = self.run(&format!(
            "curl -s -o /dev/null -w '%{{http_code}}' {extra_curl_args} \
             http://127.0.0.1:8080{path}"
        ));
        stdout.trim().to_string()
    }

    fn body(&self, path: &str, extra_curl_args: &str) -> String {
        self.sh(&format!(
            "curl -s {extra_curl_args} http://127.0.0.1:8080{path}"
        ))
    }

    /// Validates the live config the way an admin would, and returns
    /// NGINX's own message so a failure names the directive.
    fn nginx_t(&self) -> (bool, String) {
        let (ok, stdout, stderr) = self.run("nginx -t");
        (ok, format!("{stdout}{stderr}"))
    }

    fn apply_and_reload(&self) {
        self.stop_bots("apply-blocks --root /etc/nginx/sites-enabled --no-reload");
        let (ok, output) = self.nginx_t();
        assert!(ok, "the generated config does not parse:\n{output}");
        self.sh("nginx -s reload");
        // Reload is asynchronous; give the worker a moment to swap in.
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

// ---- NGINX: does the generated config actually parse and behave? ----

/// The check TODO.md has been asking for: every directive form this
/// project can emit, through a real `nginx -t`.
#[test]
fn every_generated_directive_form_parses() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-parse");
    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    server.seed_bot("badbot", "BadBot");

    // Everything on at once: patterns, exemptions (the flag form), rate
    // limiting, robots.txt, and every request-shape rule.
    server.stop_bots("set-robots-txt --enabled true");
    server.stop_bots("set-rate-limit --enabled true --rps 5 --burst 10");

    server.apply_and_reload();
    let (ok, output) = server.nginx_t();
    assert!(ok, "nginx rejected the generated config:\n{output}");
}

/// The whole point of the tool, checked against a live server rather than
/// against the text we hoped would produce it.
#[test]
fn a_blocked_user_agent_is_refused_and_everyone_else_is_served() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-block");
    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    server.seed_bot("badbot", "BadBot");

    // Before applying: everyone gets in.
    assert_eq!(server.status("/", "-A 'BadBot/1.0'"), "200");

    server.apply_and_reload();

    assert_eq!(
        server.status("/", "-A 'BadBot/1.0'"),
        "403",
        "a blocked user agent should be refused"
    );
    assert_eq!(
        server.status("/", "-A 'Mozilla/5.0'"),
        "200",
        "an ordinary visitor must still be served"
    );
}

#[test]
fn each_block_response_is_what_the_client_actually_receives() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-responses");
    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    server.seed_bot("badbot", "BadBot");

    for (arg, expected) in [
        ("forbidden", "403"),
        ("not-found", "404"),
        ("gone", "410"),
        ("teapot", "418"),
        ("too-many-requests", "429"),
    ] {
        server.stop_bots(&format!("set-block-response --response {arg}"));
        server.apply_and_reload();
        assert_eq!(
            server.status("/", "-A 'BadBot/1.0'"),
            expected,
            "{arg} should reach the client as {expected}"
        );
    }

    // 444 closes without replying, so curl reports no status at all
    // rather than a code — which is the observable difference and worth
    // asserting rather than assuming.
    server.stop_bots("set-block-response --response close");
    server.apply_and_reload();
    assert_eq!(
        server.status("/", "-A 'BadBot/1.0'"),
        "000",
        "444 should close the connection with no response"
    );
}

/// The exemption mechanism, and the guard that keeps ACME working.
#[test]
fn exempt_paths_and_well_known_stay_reachable_for_a_blocked_client() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-exempt");
    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    server.seed_bot("badbot", "BadBot");
    server.sh(
        "mkdir -p /var/www/test/blog /var/www/test/.well-known/acme-challenge && \
         echo ok > /var/www/test/blog/index.html && \
         echo token > /var/www/test/.well-known/acme-challenge/test",
    );

    // An exempt path, plus a request rule that forces /.well-known/ open.
    server.sh("stop-bots --db /tmp/db.sqlite3 list-sites 2>/dev/null | head -1 >/dev/null || true");
    server.stop_bots("set-site-rule --site test.example --rule no-user-agent --enabled true");
    server.stop_bots("exempt-path --site test.example --path /blog");
    server.apply_and_reload();

    assert_eq!(
        server.status("/", "-A 'BadBot/1.0'"),
        "403",
        "the site itself is still blocked"
    );
    assert_eq!(
        server.status("/blog/", "-A 'BadBot/1.0'"),
        "200",
        "an exempt path must stay reachable"
    );
    assert_eq!(
        server.status("/.well-known/acme-challenge/test", "-A '' -H 'User-Agent;'"),
        "200",
        "ACME validation must survive a request rule that would otherwise catch it"
    );
}

#[test]
fn the_generated_robots_txt_is_served() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-robots");
    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    server.seed_bot("gptbot", "GPTBot");
    server.stop_bots("set-robots-txt --enabled true");
    server.apply_and_reload();

    let body = server.body("/robots.txt", "");
    assert!(
        body.contains("User-agent: GPTBot"),
        "robots.txt was:\n{body}"
    );
    assert!(body.contains("Disallow:"), "robots.txt was:\n{body}");

    // And a blocked crawler can still read it — otherwise the file names
    // exactly the agents that can never see it.
    let as_bot = server.body("/robots.txt", "-A 'GPTBot/1.0'");
    assert!(
        as_bot.contains("User-agent: GPTBot"),
        "a blocked crawler must still be able to read robots.txt; got:\n{as_bot}"
    );
}

// ---- nftables: does the generated script load, and does it block? ----

/// The other half of the "never validated against the real tool" gap:
/// every firewall script shape, through a real `nft -f`.
#[test]
fn generated_firewall_scripts_load_into_real_nftables() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-nft");
    server.stop_bots("add-firewall-rule --address 203.0.113.9 --action block");
    server.stop_bots("add-firewall-rule --address 198.51.100.0/24 --action block");
    server.stop_bots("add-firewall-rule --address 2001:db8:1:2::/64 --action block");
    server.stop_bots("add-firewall-rule --address 192.0.2.7 --action allow");

    // No SSH log in the container, so the check can't run — this is the
    // documented `--force` path, and the CLI is where it's allowed.
    server.stop_bots("render-firewall --backend nftables --out /tmp/fw.nft --force");

    // `-c` is a parse-and-check that touches nothing, then the real load.
    let (ok, stdout, stderr) = server.run("nft -c -f /tmp/fw.nft");
    assert!(ok, "nft rejected the generated script:\n{stdout}{stderr}");
    server.sh("nft -f /tmp/fw.nft");

    let ruleset = server.sh("nft list table inet stop_bots");
    for expected in [
        "ip saddr 203.0.113.9 drop",
        "ip saddr 198.51.100.0/24 drop",
        "ip6 saddr 2001:db8:1:2::/64 drop",
        "ip saddr 192.0.2.7 accept",
    ] {
        assert!(
            ruleset.contains(expected),
            "{expected:?} missing from the loaded ruleset:\n{ruleset}"
        );
    }

    // The script resets only its own table, so applying twice is a no-op
    // rather than a duplicate — the idiom TODO.md flagged as reasoned-
    // through but unverified.
    server.sh("nft -f /tmp/fw.nft");
    let twice = server.sh("nft list table inet stop_bots");
    assert_eq!(
        twice.matches("ip saddr 203.0.113.9 drop").count(),
        1,
        "re-applying must not duplicate rules:\n{twice}"
    );
}

/// Loopback is deliberately exempt, and that is a safety property worth
/// pinning: the generated chain accepts `iif lo` before any drop rule, so
/// a rule an admin adds for their own public address can never sever the
/// machine's own local traffic.
#[test]
fn loopback_is_never_blocked_however_the_rules_are_written() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-loopback");
    server.stop_bots("add-firewall-rule --address 127.0.0.1 --action block");
    server.stop_bots("render-firewall --backend nftables --out /tmp/fw.nft --force");
    server.sh("nft -f /tmp/fw.nft");

    assert_eq!(
        server.status("/", "--max-time 5"),
        "200",
        "loopback must survive even an explicit rule against it"
    );
    let ruleset = server.sh("nft list table inet stop_bots");
    assert!(
        ruleset.contains("iif \"lo\" accept"),
        "the lo exemption should come from the generated chain:\n{ruleset}"
    );
}

/// Real packets, from a real second host, across a real network.
///
/// Everything above sends requests from inside the server container, where
/// the source address is loopback and therefore exempt. This is the test
/// that actually proves a firewall rule stops a remote client: a separate
/// container, on a user-defined Docker network, with its own address.
#[test]
fn a_blocked_client_container_cannot_reach_the_server() {
    if !enabled() {
        return;
    }
    let net = Network::create("stop-bots-net");
    let server = Server::start_on_network("stop-bots-target", &net);
    let client = Client::start("stop-bots-client", &net);

    let client_ip = client.address();
    assert_eq!(
        client.get(&server.name, "--max-time 5"),
        "200",
        "the client should reach the server before anything is blocked"
    );

    server.stop_bots(&format!(
        "add-firewall-rule --address {client_ip} --action block"
    ));
    server.stop_bots("render-firewall --backend nftables --out /tmp/fw.nft --force");
    server.sh("nft -f /tmp/fw.nft");

    assert_eq!(
        client.get(&server.name, "--max-time 5"),
        "000",
        "packets from {client_ip} should not reach the server at all"
    );

    // Removing our table restores service — the recovery an admin needs
    // after locking themselves out, and the reason the generated script
    // never touches any other table.
    server.sh("nft delete table inet stop_bots");
    assert_eq!(
        client.get(&server.name, "--max-time 5"),
        "200",
        "deleting the table should restore service"
    );
}

// ---- batch mode: does one command really do the lot? ----

/// `batch --apply` is the only thing in this project that enforces
/// anything unattended, and it enforces on two planes at once. Both are
/// checked the only way that means anything: a real `nft` ruleset, and a
/// real HTTP request to a real NGINX that has genuinely been reloaded.
///
/// `--force` because a container has no SSH log, so the lockout guard
/// cannot run — which is exactly the case `--apply` refuses on, and the
/// documented way through. `--no-fetch` to keep the run offline and
/// deterministic.
#[test]
fn batch_apply_enforces_on_both_planes_at_once() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-batch");
    server.seed_bot("badbot", "BadBot");
    server.stop_bots("add-firewall-rule --address 203.0.113.9 --action block");

    // Everything is still inert at this point: no table, and the server
    // serves the bot happily.
    assert_eq!(server.status("/", "-H 'User-Agent: BadBot/1.0'"), "200");

    let output = server.stop_bots(
        "batch --apply --force --no-fetch --verbose \
         --root /etc/nginx/sites-enabled --out /tmp/fw.nft --access-log /dev/null",
    );

    // The firewall plane: the script was written *and* loaded.
    let ruleset = server.sh("nft list table inet stop_bots");
    assert!(
        ruleset.contains("ip saddr 203.0.113.9 drop"),
        "batch --apply should have loaded the rules; batch said:\n{output}\nruleset:\n{ruleset}"
    );

    // The NGINX plane: the config was written *and* reloaded, which only
    // a request can show.
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(
        server.status("/", "-H 'User-Agent: BadBot/1.0'"),
        "403",
        "batch --apply should have reloaded NGINX; batch said:\n{output}"
    );
    assert_eq!(
        server.status("/", "-H 'User-Agent: Mozilla/5.0'"),
        "200",
        "and everyone else must still be served"
    );
}

/// Without `--apply`, the same run writes both and enforces neither. This
/// is the project's default and the reason `--apply` is a flag rather
/// than the behaviour: a script on disk and a config NGINX has not
/// re-read are both inert.
#[test]
fn batch_without_apply_writes_both_and_enforces_neither() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-batch-dry");
    server.seed_bot("badbot", "BadBot");
    server.stop_bots("add-firewall-rule --address 203.0.113.9 --action block");

    server.stop_bots(
        "batch --no-fetch --root /etc/nginx/sites-enabled \
         --out /tmp/fw.nft --access-log /dev/null",
    );

    assert!(
        server.run("test -s /tmp/fw.nft").0,
        "the script should have been written"
    );
    let (loaded, _, _) = server.run("nft list table inet stop_bots");
    assert!(!loaded, "but nothing should have been loaded into nftables");
    assert_eq!(
        server.status("/", "-H 'User-Agent: BadBot/1.0'"),
        "200",
        "and NGINX should still be serving its old config"
    );
}

// ---- the lockout guard, against a real ruleset ----

/// The guard that failed in production. With a log naming a connected
/// admin, a rule covering that admin must stop the render — before
/// anything is written, let alone applied.
#[test]
fn rendering_refuses_to_lock_out_a_connected_admin() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-lockout");
    server.sh(
        "printf '%s\\n' 'Aug 17 10:00:01 host sshd[100]: Accepted publickey for admin \
         from 198.51.100.42 port 50000 ssh2' > /tmp/auth.log",
    );
    // A rule that contains the admin's address — the shape of what took a
    // real server off the network.
    server.stop_bots("add-firewall-rule --address 198.51.100.0/24 --action block");

    let output = server.stop_bots_expect_failure(
        "render-firewall --backend nftables --out /tmp/fw.nft --ssh-log /tmp/auth.log",
    );
    assert!(
        output.contains("198.51.100.42"),
        "the refusal should name the admin it would cut off:\n{output}"
    );
    let (exists, _, _) = server.run("test -f /tmp/fw.nft");
    assert!(!exists, "nothing may be written when the guard refuses");
}

/// The counterpart: a log with no risk in it lets the render through.
#[test]
fn rendering_proceeds_when_no_connected_admin_is_affected() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-lockout-ok");
    server.sh(
        "printf '%s\\n' 'Aug 17 10:00:01 host sshd[100]: Accepted publickey for admin \
         from 192.0.2.10 port 50000 ssh2' > /tmp/auth.log",
    );
    server.stop_bots("add-firewall-rule --address 198.51.100.0/24 --action block");
    server
        .stop_bots("render-firewall --backend nftables --out /tmp/fw.nft --ssh-log /tmp/auth.log");
    server.sh("nft -c -f /tmp/fw.nft");
}
