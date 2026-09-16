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
//! **They do not run by default.** They need Docker, take tens of
//! seconds, and would break `cargo test` on any machine without a
//! container runtime. Set `STOP_BOTS_CONTAINER_TESTS=1` to enable them;
//! `make integration-test` does that for you. CI runs them as their own
//! job.
//!
//! ## Two images, because faithfulness is not free
//!
//! [`Server`] (`Dockerfile`, ubuntu:24.04) has **no init system**. It is
//! fast, needs only `NET_ADMIN`, and is what the NGINX and nftables tests
//! use — `nginx -s reload` stands in for `systemctl reload nginx`. What it
//! is faithful about is the two parsers this project cannot check any
//! other way.
//!
//! [`Host`] (`Dockerfile.host`, debian:13) runs **real systemd as PID 1**.
//! It exists because that "no init system" line above was, for a while,
//! the reason three separate bugs reached a live server: `install web`
//! failing with `203/EXEC` because the unit's `ProtectHome=yes` hid the
//! binary, the firewall apply failing because `RestrictAddressFamilies`
//! omitted `AF_NETLINK`, and a deploy that replaced the binary without
//! restarting anything. Every one of those is a property of the generated
//! unit under a real service manager, and no amount of asserting on the
//! unit's *text* finds them — the text was what everyone had already
//! read.
//!
//! Tests on `Host` derive their probes from the unit `install web`
//! actually wrote (see [`Host::oneshot_under_web_sandbox`]) rather than
//! from a hand-written copy, and the sandbox ones each carry a negative
//! control that removes the directive under test and asserts the failure
//! comes back. Without that control, a container where the sandbox
//! silently did not apply would pass every one of them.

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
         (or run `make integration-test`) to enable them."
    );
    false
}

const IMAGE: &str = "stop-bots-test:latest";

/// The image with a real init — see `Dockerfile.host` and [`Host`].
const HOST_IMAGE: &str = "stop-bots-host:latest";

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

/// The same, for the systemd image. A separate `Once` so a run that only
/// touches one of the two images only builds that one.
fn build_host_image() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let ctx = stage_binary();
        let out = Command::new("docker")
            .args([
                "build",
                "-q",
                "-f",
                &format!("{ctx}/Dockerfile.host"),
                "-t",
                HOST_IMAGE,
                &ctx,
            ])
            .output()
            .expect("failed to run docker build");
        assert!(
            out.status.success(),
            "docker build (host image) failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    });
}

/// Copies the binary under test into the build context and returns the
/// context path.
///
/// `CARGO_BIN_EXE_stop-bots` is the exact binary this test run compiled —
/// not whatever happens to be on `PATH`.
///
/// Guarded by a `Once` of its own, and that is the point. The two image
/// builders above have one `Once` each, which stops two threads racing to
/// build *the same* image — but both of them call this, and both write the
/// same file. So a thread staging for the host image could truncate and
/// rewrite `stop-bots` while the other image's `docker build` was reading
/// it, putting a half-copied binary inside the image: exactly the failure
/// the per-image `Once`es were added for, arriving through the one door
/// they left open. It presents as a scatter of unrelated-looking command
/// failures, and it is far likelier on a slow two-core runner with a cold
/// Docker cache than on a developer's machine — which is where it was
/// found, as three consecutive red `container` jobs on CI with a green
/// suite locally.
///
/// `call_once` blocks every other caller until the copy has finished, so
/// the file is only ever read complete.
fn stage_binary() -> String {
    static ONCE: std::sync::Once = std::sync::Once::new();
    let manifest = env!("CARGO_MANIFEST_DIR");
    let ctx = format!("{manifest}/tests/container");
    ONCE.call_once(|| {
        std::fs::copy(env!("CARGO_BIN_EXE_stop-bots"), format!("{ctx}/stop-bots"))
            .expect("failed to stage the stop-bots binary into the build context");
    });
    ctx
}

fn build_image_now() {
    let ctx = stage_binary();
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

/// The subnet every test network is given.
///
/// **Not Docker's default.** Docker hands out RFC1918 addresses, and every
/// detector in this project deliberately skips those —
/// `accesslog::is_local_or_private` is what stops a NAT gateway or a
/// reverse proxy getting the whole office blocked. A client on
/// `192.168.x.x` is therefore invisible to detection, and an end-to-end
/// test built on one passes by finding nothing, for ever.
///
/// TEST-NET-2, reserved by RFC 5737 for documentation: it is not private,
/// so the detectors treat it as a real remote client, and it can never
/// route anywhere outside the container network.
///
/// Carved into /28s because tests run in parallel and Docker refuses two
/// networks whose pools overlap. Sixteen is far more than the handful of
/// networked tests here, and each gets thirteen usable addresses.
fn test_subnet(index: usize) -> String {
    format!("198.51.100.{}/28", (index % 16) * 16)
}

impl Network {
    fn create(name: &str) -> Network {
        let _ = Command::new("docker")
            .args(["network", "rm", name])
            .output();

        // Retry across slices rather than pick one and hope: a network
        // left behind by an aborted run still holds its pool, and the
        // failure ("Pool overlaps with other one on this address space")
        // names neither which network nor which test.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let mut last = String::new();
        for _ in 0..16 {
            let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let subnet = test_subnet(index);
            let out = Command::new("docker")
                .args(["network", "create", "--subnet", &subnet, name])
                .output()
                .expect("failed to create a docker network");
            if out.status.success() {
                return Network {
                    name: name.to_string(),
                };
            }
            last = String::from_utf8_lossy(&out.stderr).to_string();
        }
        panic!("docker network create failed for every subnet slice:\n{last}");
    }
}

/// Runs a shell command inside a container, returning (exit status
/// success, stdout, stderr). The one `docker exec` every assertion in this
/// file flows through.
fn exec_in(container: &str, cmd: &str) -> (bool, String, String) {
    let out = Command::new("docker")
        .args(["exec", container, "sh", "-c", cmd])
        .output()
        .expect("failed to run docker exec");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// [`exec_in`], asserting the command succeeded.
fn sh_in(container: &str, cmd: &str) -> String {
    let (ok, stdout, stderr) = exec_in(container, cmd);
    assert!(
        ok,
        "command failed: {cmd}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    stdout
}

/// `docker rm -f`, for the `Drop` impls. Errors are ignored: a container
/// that is already gone is the outcome wanted.
fn remove_container(name: &str) {
    let _ = Command::new("docker").args(["rm", "-f", name]).output();
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

    /// Fetches `path` from `host` and returns the status code.
    fn get_path(&self, host: &str, path: &str, extra: &str) -> String {
        let out = Command::new("docker")
            .args([
                "exec",
                &self.name,
                "sh",
                "-c",
                &format!(
                    "curl -s -o /dev/null -w '%{{http_code}}' {extra} http://{host}:8080{path}"
                ),
            ])
            .output()
            .expect("failed to run curl in the client container");
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
        remove_container(&self.name);
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
        exec_in(&self.name, cmd)
    }

    /// Runs a command and asserts it succeeded.
    fn sh(&self, cmd: &str) -> String {
        sh_in(&self.name, cmd)
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

    /// The same, against another port — for the two-site tests, where the
    /// second `server` block is what has to behave differently.
    fn status_on(&self, port: u16, path: &str, extra_curl_args: &str) -> String {
        let (_, stdout, _) = self.run(&format!(
            "curl -s -o /dev/null -w '%{{http_code}}' {extra_curl_args} \
             http://127.0.0.1:{port}{path}"
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
        remove_container(&self.name);
    }
}

// ---- a real Debian host, with a real init ----

/// A container running systemd as PID 1, cleaned up on drop.
///
/// Separate from [`Server`] because the privileges differ and the boot
/// cost is real: this one needs `SYS_ADMIN` and an unconfined seccomp
/// profile, and takes a couple of seconds to reach `running`. Tests that
/// only need NGINX and `nft` should keep using `Server`, which needs
/// neither.
struct Host {
    name: String,
}

/// Where `stop-bots install web` puts the console's database on a host.
const HOST_DB: &str = "/var/lib/stop-bots/db.sqlite3";

impl Host {
    /// A booted host with NGINX running — every test here wants that
    /// much, so it is not a line they each repeat. See [`Host::installed`]
    /// for the next step most of them take.
    fn start(name: &str) -> Host {
        let host = Host::boot(name);
        host.sh("systemctl start nginx");
        host
    }

    /// [`Host::start`] with the console installed as a service, the way
    /// `stop-bots install web` leaves a real host. For the tests that
    /// exercise the *installed* host rather than the install itself.
    fn installed(name: &str) -> Host {
        let host = Host::start(name);
        host.sh("stop-bots install web");
        host
    }

    /// Runs `stop-bots` on the host against the installed console's
    /// database. `--db` is a per-subcommand flag, so it goes last.
    fn stop_bots(&self, args: &str) -> String {
        self.sh(&format!("stop-bots {args} --db {HOST_DB}"))
    }

    fn boot(name: &str) -> Host {
        build_host_image();
        // Leftover from a previous aborted run.
        let _ = Command::new("docker").args(["rm", "-f", name]).output();

        let out = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                name,
                // systemd needs to mount things: every `Protect*` and
                // `Private*` directive in the generated unit is a mount
                // namespace, and without this they are silently not
                // applied — which would make every assertion below pass
                // for the wrong reason.
                "--cap-add=SYS_ADMIN",
                // `nft` and `iptables` manipulate the container's own
                // netfilter tables, same as `Server`.
                "--cap-add=NET_ADMIN",
                // Docker's outer seccomp and AppArmor profiles block
                // syscalls systemd needs to boot at all. Turning them off
                // does *not* weaken what is under test: `RestrictAddress\
                // Families` is enforced by a seccomp filter systemd
                // installs itself, inside the unit, and it was verified to
                // still refuse AF_NETLINK with these off.
                "--security-opt",
                "seccomp=unconfined",
                "--security-opt",
                "apparmor=unconfined",
                "--cgroupns=host",
                "-v",
                "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                "--tmpfs",
                "/run",
                "--tmpfs",
                "/run/lock",
                HOST_IMAGE,
            ])
            .output()
            .expect("failed to run docker run");
        assert!(
            out.status.success(),
            "docker run (host) failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );

        let host = Host {
            name: name.to_string(),
        };
        host.wait_for_boot();
        host
    }

    /// Blocks until systemd says the system is up.
    ///
    /// `degraded` counts: this image has units masked out of the boot
    /// (see `Dockerfile.host`), and a masked unit is a failed job as far
    /// as `is-system-running` is concerned. What matters is that the
    /// manager is accepting jobs, which both states mean.
    fn wait_for_boot(&self) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let mut last = String::new();
        while std::time::Instant::now() < deadline {
            let (_, stdout, stderr) = self.run("systemctl is-system-running");
            last = format!("{stdout}{stderr}");
            match last.trim() {
                "running" | "degraded" => return,
                _ => std::thread::sleep(std::time::Duration::from_millis(200)),
            }
        }
        panic!("systemd never finished booting; last state was {last:?}");
    }

    /// Runs a shell command inside the container, returning
    /// (exit status success, stdout, stderr).
    fn run(&self, cmd: &str) -> (bool, String, String) {
        exec_in(&self.name, cmd)
    }

    /// Waits for `path` to appear inside the container, up to 30s.
    ///
    /// The deploy tests prove a restart re-executed the *new* binary by
    /// having it `touch` a marker file. `systemctl` reporting the unit
    /// `active` does not mean that has happened yet: these units are
    /// `Type=simple`, where systemd calls the service started as soon as
    /// it has forked the process — everything the process then does,
    /// including running the first line of a shell wrapper, happens after
    /// the `systemctl` command has already returned. The gap is
    /// microseconds on an idle machine and wide enough to lose on a
    /// loaded one, which is how this reached CI as an occasional
    /// "re-executed the old binary" with nothing wrong: found here by
    /// running the suite while a full rebuild competed for the same cores.
    ///
    /// Only for assertions that something *will* appear. A test asserting
    /// a marker is absent must not wait, or it proves nothing — see the
    /// negative check in `redeploying_over_a_running_console_restarts_it`.
    fn wait_for_file(&self, path: &str) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if self.run(&format!("test -e {path}")).0 {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    /// [`Self::run`], retried while SQLite says the database is locked.
    ///
    /// A CLI command and the console service are two processes sharing one
    /// file, which is the arrangement this project is built around: `Db`
    /// sets a five-second busy timeout precisely so the short collisions
    /// between them resolve by waiting. That is enough on any real host and
    /// enough here on an idle machine — but this suite runs a dozen
    /// containers at once, and on an oversubscribed two-core CI runner the
    /// same five seconds can elapse inside one query's scheduling gaps. The
    /// suite was three times red on CI and green locally until a loaded
    /// machine reproduced it here in one run.
    ///
    /// So the retry is about the test harness's own contention, not about
    /// papering over a lock bug: these assertions are about what the report
    /// *says*, and a reader that lost a race has not said anything yet.
    /// Raising the production timeout to suit a test bench would be the
    /// wrong direction — five seconds is chosen so that a genuine deadlock
    /// still surfaces as an error instead of a hang.
    fn run_uncontended(&self, cmd: &str) -> (bool, String, String) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let (ok, stdout, stderr) = self.run(cmd);
            let said = format!("{stdout}{stderr}");
            if !said.contains("database is locked") {
                return (ok, stdout, stderr);
            }
            if std::time::Instant::now() >= deadline {
                panic!("`{cmd}` never got the database lock in 30s:\n{said}");
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    /// Runs a command and asserts it succeeded.
    fn sh(&self, cmd: &str) -> String {
        sh_in(&self.name, cmd)
    }

    /// One property of a unit, as systemd itself reports it.
    ///
    /// Read through `systemctl show` rather than by parsing `systemctl
    /// status`: the status text is for humans and changes between
    /// versions, while these property names are stable and the values are
    /// exactly what the manager decided.
    fn unit(&self, unit: &str, property: &str) -> String {
        self.sh(&format!("systemctl show -p {property} --value {unit}"))
            .trim()
            .to_string()
    }

    /// What the journal has for a unit — the only place a sandbox refusal
    /// leaves its reason, and the reason is the whole point of these
    /// tests.
    fn journal(&self, unit: &str) -> String {
        let (_, stdout, stderr) = self.run(&format!("journalctl -u {unit} --no-pager -o cat"));
        format!("{stdout}{stderr}")
    }

    /// Starts a unit without asserting it worked, for the cases where
    /// failing *is* the expected outcome.
    fn try_start(&self, unit: &str) -> bool {
        self.run(&format!("systemctl start {unit}")).0
    }

    /// The live nftables ruleset.
    fn ruleset(&self) -> String {
        self.sh("nft list ruleset")
    }

    /// Copies a file from the working tree into the container.
    ///
    /// Not into `/tmp`: systemd mounts a tmpfs there during boot, which
    /// shadows whatever `docker cp` wrote into the image's own `/tmp`.
    /// The copy reports success and the file is not there.
    fn put(&self, local: &str, remote: &str) {
        let out = Command::new("docker")
            .args(["cp", local, &format!("{}:{remote}", self.name)])
            .output()
            .expect("failed to run docker cp");
        assert!(
            out.status.success(),
            "docker cp {local} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Blocks until the console answers, meaning its start-up writes to
    /// the database are done.
    ///
    /// Needed because `Db::open` sets no `busy_timeout`, so a second
    /// process that wants the database *while the console is still
    /// registering sources and running due cron jobs* gets an immediate
    /// "database is locked" rather than waiting a moment. That is a real
    /// rough edge — see TODO.md — and this poll keeps these tests from
    /// racing it. It is not hiding it: nothing here would have found it,
    /// and a flaky test would have hidden it better.
    fn wait_for_console(&self) {
        self.wait_for_console_at("");
    }

    /// The same, for a console serving under a path prefix.
    ///
    /// A prefixed console does not answer on `/login` at all — the prefix
    /// is part of every route it matches, which is the whole reason it has
    /// to be told about one. Polling the unprefixed path after a Web
    /// Access change is how this helper first reported a healthy console
    /// as dead.
    fn wait_for_console_at(&self, base: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            let (ok, code, _) = self.run(&format!(
                "curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:8787{base}/login"
            ));
            if ok && code.trim().starts_with('2') {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        panic!(
            "the console never answered on 127.0.0.1:8787{base}/login. journal:\n{}",
            self.journal("stop-bots-web.service")
        );
    }

    /// Installs the console and logs into it, returning a handle that can
    /// post actions the way a browser does.
    ///
    /// The password comes from the installer's own output, which is the
    /// only place it is ever shown — so this also exercises the claim that
    /// an operator can actually get in with what they were handed.
    fn console(&self) -> Console {
        let out = self.sh("stop-bots install web");
        let password = out
            .lines()
            .map(str::trim)
            .find(|line| line.len() > 20 && !line.contains(' '))
            .unwrap_or_else(|| panic!("no password in the installer output:\n{out}"))
            .to_string();
        self.wait_for_console();

        // A cookie jar, so the session survives across calls exactly as it
        // would in a browser.
        let login = self.sh(&format!(
            "curl -s -o /dev/null -w '%{{http_code}}' -c /tmp/jar              --data-urlencode 'password={password}' http://127.0.0.1:8787/login"
        ));
        assert!(
            login.trim().starts_with('2') || login.trim().starts_with('3'),
            "logging in with the installer's own password returned {login}"
        );
        Console {
            name: self.name.clone(),
        }
    }

    /// The stored console password hash, read with the tool's own
    /// database rather than by poking at SQLite's file format.
    fn password_hash(&self) -> String {
        self.sh(&format!(
            "sqlite3 {HOST_DB} \"select value from settings where key like 'web:password%'\""
        ))
        .trim()
        .to_string()
    }

    /// Seeds one blocked bot through the real parser, so an apply has
    /// something to write. Same format and same reasoning as
    /// [`Server::seed_bot`].
    fn seed_bot(&self, id: &str, pattern: &str) {
        let json = format!(
            r#"[{{"id":"{id}","categories":["ai"],"pattern":{{"accepted":["{pattern}"],"forbidden":[]}},"url":"https://example.invalid/{id}"}}]"#
        );
        self.sh(&format!("cat > /tmp/bots.json <<'JSON'\n{json}\nJSON"));
        self.stop_bots("update-bot-lists --source /tmp/bots.json");
    }

    /// Runs `command` as a oneshot unit carrying **the generated web
    /// unit's own sandbox**, and returns whether it succeeded.
    ///
    /// The unit is derived from `/etc/systemd/system/stop-bots-web.service`
    /// as `install web` wrote it — every `Protect*`, `Restrict*` and
    /// `Private*` line is carried over verbatim, and only `ExecStart` and
    /// `Type` are replaced. That is the whole point: a hand-written unit
    /// listing the directives this test expects would pass forever,
    /// including on the day the generated one stops emitting one of them.
    ///
    /// `mangle` edits the derived unit before it is installed, so a test
    /// can prove its own teeth by removing a directive and watching the
    /// command fail.
    fn oneshot_under_web_sandbox(&self, probe: &str, command: &str, mangle: &str) -> bool {
        self.sh(&format!(
            "set -e\n\
             sed -e 's|^ExecStart=.*|ExecStart={command}|' \
                 -e 's|^Type=.*|Type=oneshot|' \
                 -e 's|^Restart=.*||' \
                 /etc/systemd/system/{unit} {mangle} \
                 > /etc/systemd/system/{probe}.service\n\
             systemctl daemon-reload",
            unit = "stop-bots-web.service",
        ));
        self.try_start(&format!("{probe}.service"))
    }
}

/// A logged-in session against the console running inside a [`Host`].
///
/// Drives it over real HTTP through the container's own `curl`, rather
/// than through the router in-process the way `tests/web.rs` does. That is
/// the point: this is the only place the console is a listening server
/// with a session cookie, talking to a real NGINX and a real `nft`.
struct Console {
    name: String,
}

impl Console {
    fn run(&self, cmd: &str) -> (bool, String, String) {
        exec_in(&self.name, cmd)
    }

    /// Fetches a page as the logged-in user.
    fn get(&self, path: &str) -> String {
        let (ok, stdout, stderr) =
            self.run(&format!("curl -s -b /tmp/jar http://127.0.0.1:8787{path}"));
        assert!(ok, "GET {path} failed:\n{stderr}");
        stdout
    }

    /// The CSRF token currently on `path`. Every form carries one, and a
    /// post without it is refused — so reading it back out is part of
    /// behaving like a browser, not a way around the check.
    fn csrf(&self, path: &str) -> String {
        let body = self.get(path);
        let marker = r#"name="csrf" value=""#;
        let start = body
            .find(marker)
            .unwrap_or_else(|| panic!("no csrf token on {path}"))
            + marker.len();
        body[start..]
            .split('"')
            .next()
            .expect("an unterminated csrf value")
            .to_string()
    }

    /// Posts a form the way the page's own button would, token included.
    /// Returns the flash message the console redirected to.
    fn post(&self, path: &str, fields: &[(&str, &str)]) -> String {
        let csrf = self.csrf("/");
        let mut args = format!("--data-urlencode 'csrf={csrf}'");
        for (key, value) in fields {
            args.push_str(&format!(" --data-urlencode '{key}={value}'"));
        }
        let (ok, stdout, stderr) = self.run(&format!(
            "curl -s -L -b /tmp/jar -c /tmp/jar {args} http://127.0.0.1:8787{path}"
        ));
        assert!(ok, "POST {path} failed:\n{stderr}");
        stdout
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        remove_container(&self.name);
    }
}

// ---- `install web`: the unit, and the sandbox it puts the service in ----

/// The install path an operator actually runs, on a host that has an init
/// to talk to.
///
/// Every part of this was unit-tested against a fake `systemctl` before
/// today, and all of it passed while the real thing failed on a real host
/// — twice. The difference is that nothing was asking systemd.
#[test]
fn install_web_writes_a_unit_that_systemd_actually_starts() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-install");

    let out = host.sh("stop-bots install web");
    assert!(
        out.contains("stop-bots-web.service"),
        "install said nothing about the unit:\n{out}"
    );

    // The installer must be the one that generated the password, because
    // it is the only one that shows it to anybody. `install web` used to
    // start the service *before* doing its database work, so the service
    // could win the race, generate a password of its own, and leave the
    // installer reporting "a console password is already set, keeping it"
    // — an install that completes and hands the operator nothing. The
    // other two ways that race landed were a service that crash-looped on
    // "database is locked" and an install that failed after having already
    // enabled the unit.
    assert!(
        out.contains("Console password:"),
        "the installer did not generate and print the password:\n{out}"
    );

    assert_eq!(host.unit("stop-bots-web.service", "LoadState"), "loaded");
    assert_eq!(
        host.unit("stop-bots-web.service", "ActiveState"),
        "active",
        "the service is not running. journal:\n{}",
        host.journal("stop-bots-web.service")
    );
    assert_eq!(
        host.unit("stop-bots-web.service", "UnitFileState"),
        "enabled",
        "`enable --now` did not enable it, so it would not come back on boot"
    );
}

/// **The netlink bug, reproduced and then fixed, in one test.**
///
/// `nft` and Debian's nft-backed `iptables` reach the kernel over a
/// netlink socket. The generated unit used to write
/// `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` under a comment
/// asserting the service never applies the firewall — which stopped being
/// true the moment applying was added. The failure on the real host was
/// `Unable to initialize Netlink socket: Address family not supported by
/// protocol`, which names neither systemd nor this project.
///
/// The negative control is not decoration. Without it this test passes
/// whether or not the sandbox is being enforced at all, and "the sandbox
/// silently did not apply" is the one way a container can lie about this.
#[test]
fn the_generated_sandbox_lets_the_firewall_reach_netlink() {
    if !enabled() {
        return;
    }
    let host = Host::installed("stop-bots-netlink");

    host.stop_bots("add-firewall-rule --address 203.0.113.9");
    // `batch --apply` rather than a bespoke verb: it is the only thing
    // that applies the firewall unattended, and it is what a real cron
    // entry runs — so this probes the sandbox through the same call the
    // host does. `--force` because a container has no SSH log for the
    // lockout guard to read, `--no-fetch` to keep the run offline.
    let apply = format!(
        "/usr/local/bin/stop-bots batch --apply --force --no-fetch \
         --root /etc/nginx/sites-enabled --out /etc/stop-bots/firewall.nft --db {HOST_DB}"
    );

    // First the control: strip AF_NETLINK back out, and the apply must
    // fail the way the real host did.
    let without = host.oneshot_under_web_sandbox(
        "probe-without-netlink",
        &apply,
        "| sed -e 's/ AF_NETLINK//'",
    );
    assert!(
        !without,
        "stripping AF_NETLINK from the unit did not break the apply, so this \
         test cannot tell whether the sandbox is enforced at all"
    );
    let journal = host.journal("probe-without-netlink.service");
    assert!(
        journal.contains("Netlink"),
        "the failure was not the netlink one, so the control proves nothing:\n{journal}"
    );

    // Then the unit as generated: the same command, through the same
    // sandbox, has to work.
    let with = host.oneshot_under_web_sandbox("probe-with-netlink", &apply, "");
    assert!(
        with,
        "the generated unit's sandbox blocks the firewall apply. journal:\n{}",
        host.journal("probe-with-netlink.service")
    );
    assert!(
        host.ruleset().contains("203.0.113.9"),
        "the apply reported success but the rule is not in the live ruleset"
    );
}

/// **The `install web` bug, reproduced from the report.**
///
/// A binary sitting in `/root` and a unit setting `ProtectHome=yes` is a
/// service that dies with `status=203/EXEC` and "No such file or
/// directory" for a file that is plainly there. The fix is a preflight
/// refusal that names the directive; this checks both halves, because a
/// refusal for a danger that is not real would be just as wrong.
#[test]
fn installing_from_a_hidden_directory_is_refused_before_systemd_can_fail() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-hidden");
    host.sh("cp /usr/local/bin/stop-bots /root/stop-bots");

    let (ok, stdout, stderr) = host.run("/root/stop-bots install web");
    let said = format!("{stdout}{stderr}");
    assert!(!ok, "install from /root should have been refused:\n{said}");
    assert!(
        said.contains("ProtectHome=yes"),
        "the refusal must name the directive, or it is as useless as systemd's own report:\n{said}"
    );
    assert!(
        said.contains("203/EXEC"),
        "the refusal must name the failure it is preventing:\n{said}"
    );
    assert!(
        said.contains("/usr/local/bin/stop-bots"),
        "the refusal must give a command to paste:\n{said}"
    );

    // Now prove the danger is real rather than folklore: install properly,
    // then run the /root copy through the sandbox the generated unit
    // actually sets. This is the failure the check above exists to stop.
    host.sh("stop-bots install web");
    let ran = host.oneshot_under_web_sandbox("probe-root-binary", "/root/stop-bots --version", "");
    assert!(
        !ran,
        "the generated unit does not hide /root, so the preflight refusal guards nothing"
    );
    assert_eq!(
        host.unit("probe-root-binary.service", "ExecMainStatus"),
        "203",
        "expected 203/EXEC. journal:\n{}",
        host.journal("probe-root-binary.service")
    );
}

/// The unit's own comment says `ProtectSystem=full` is deliberately absent
/// because it would make `/etc` read-only and break the first apply "an
/// hour after the unit started cleanly". That was a claim with nothing
/// behind it. This runs a real apply through the real sandbox, and then
/// through the stricter one, so the comment is a test result.
#[test]
fn the_sandbox_still_lets_the_service_rewrite_nginx_config() {
    if !enabled() {
        return;
    }
    let host = Host::installed("stop-bots-protectsystem");

    host.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    host.seed_bot("badbot", "BadBot");
    let apply = format!("/usr/local/bin/stop-bots apply-blocks --root /etc/nginx/sites-enabled --no-reload --db {HOST_DB}");

    let strict = host.oneshot_under_web_sandbox(
        "probe-protect-full",
        &apply,
        "| sed -e 's/^ProtectSystem=.*/ProtectSystem=full/'",
    );
    assert!(
        !strict,
        "ProtectSystem=full did not stop the apply, so the reason the unit gives for not using it is wrong"
    );

    let asgenerated = host.oneshot_under_web_sandbox("probe-protect-yes", &apply, "");
    assert!(
        asgenerated,
        "the generated sandbox blocks the apply it exists to allow. journal:\n{}",
        host.journal("probe-protect-yes.service")
    );
    let applied = host.sh("cat /etc/nginx/sites-enabled/test-site.conf");
    assert!(
        applied.contains("BEGIN stop-bots"),
        "the apply reported success but wrote no block into the site config:\n{applied}"
    );
    assert!(
        applied.contains("BadBot"),
        "the block is there but does not carry the seeded pattern:\n{applied}"
    );
}

/// **The `make deploy` bug.** A new binary lands, everything reports
/// success, and the console keeps serving the old code because nothing
/// restarted the unit.
///
/// The marker is a wrapper rather than `--version`, for the reason the
/// Makefile now says out loud: two builds of the same `0.0.x` are
/// indistinguishable by version, so the only honest evidence is that the
/// *new file* is what got executed.
#[test]
fn replacing_the_binary_and_restarting_runs_the_new_one() {
    if !enabled() {
        return;
    }
    let host = Host::installed("stop-bots-redeploy");

    let before = host.unit("stop-bots-web.service", "MainPID");
    assert_ne!(before, "0", "the service is not running to begin with");

    // Stand in for `make deploy`: write beside the running binary, then
    // rename over it.
    //
    // Not a `>` redirect, and that is the point — truncating a running
    // executable fails with `Text file busy`, which is exactly why the
    // Makefile scps to `$(DEPLOY_PATH).new` and moves it into place. A
    // rename swaps the directory entry and leaves the running image
    // alone, which is also why the old process keeps serving old code
    // until something restarts it.
    host.sh("cp /usr/local/bin/stop-bots /usr/local/bin/stop-bots.real");
    host.sh("printf '#!/bin/sh\\ntouch /run/new-build-ran\\nexec /usr/local/bin/stop-bots.real \"$@\"\\n' > /usr/local/bin/stop-bots.new");
    host.sh("chmod 755 /usr/local/bin/stop-bots.new");
    host.sh("mv /usr/local/bin/stop-bots.new /usr/local/bin/stop-bots");
    assert!(
        !host.run("test -e /run/new-build-ran").0,
        "the marker exists before the restart, so it proves nothing"
    );

    host.sh("systemctl try-restart stop-bots-web.service");

    let after = host.unit("stop-bots-web.service", "MainPID");
    assert_ne!(
        before, after,
        "try-restart left the old process running, which is the bug exactly"
    );
    assert_eq!(
        host.unit("stop-bots-web.service", "ActiveState"),
        "active",
        "the service did not come back. journal:\n{}",
        host.journal("stop-bots-web.service")
    );
    assert!(
        host.wait_for_file("/run/new-build-ran"),
        "the service restarted but re-executed the old binary. journal:\n{}",
        host.journal("stop-bots-web.service")
    );
}

/// The built-in bot list has to reach a host that only ever runs the
/// console — which is every host `install web` sets up.
///
/// It did not. `register_all_sources` both registers the four sources and
/// *stores* the one compiled into the binary, and it was called from the
/// TUI's startup and nowhere else. A production host running
/// `stop-bots web` therefore had no `stop-bots-extras` source row, no
/// entries, and none of its patterns in the rendered config — including
/// Let's Encrypt, which the humans-only mode relies on being allowed.
///
/// Invisible from inside: nothing failed, because nothing was asked to.
/// The source simply was not in the database for any screen to report on,
/// and the list had been derived from the access log of the very host that
/// was not using it. Only an end-to-end check catches a missing call.
#[test]
fn the_console_stores_the_built_in_bot_list_on_startup() {
    if !enabled() {
        return;
    }
    let host = Host::installed("stop-bots-builtin-list");
    host.wait_for_console();

    let entries = host.sh(&format!(
        "sqlite3 {HOST_DB} \"select count(*) from bot_source_entries where source_id = 'stop-bots-extras'\""
    ));
    let entries: i64 = entries.trim().parse().unwrap_or(0);
    assert!(
        entries > 0,
        "the console started without storing the built-in list; \
         bot_source_entries held {entries} row(s) for it"
    );

    // And the entry the humans-only allowlist is built around is one of
    // them, by pattern rather than by slug: the slug is this project's own
    // naming, the pattern is what actually has to match a request.
    let le = host.sh(&format!(
        "sqlite3 {HOST_DB} \"select count(*) from bots where user_agent_pattern like '%Let%Encrypt%'\""
    ));
    assert_eq!(
        le.trim(),
        "1",
        "Let's Encrypt is not in the merged bot list: {le}"
    );
}

/// **The deploy half of the same bug.** `make deploy` pipes
/// `scripts/deploy-remote.sh` to the target over ssh; this runs that exact
/// file against a real systemd, because it is the only part of a deploy
/// that decides whether the host keeps serving the old build.
///
/// The case that matters is a unit that is *enabled but not running* —
/// where systemd is meant to be running the console and currently is not,
/// which is precisely where a crash-looping service ends up. `try-restart`
/// does nothing at all to such a unit, so the old script would have landed
/// the new binary and left the console down.
#[test]
fn deploying_onto_a_stopped_console_starts_it_again() {
    if !enabled() {
        return;
    }
    let host = Host::installed("stop-bots-deploy-stopped");
    host.wait_for_console();
    host.put("scripts/deploy-remote.sh", "/opt/deploy-remote.sh");

    // The state a crash-loop leaves behind: enabled, so systemd is
    // supposed to be running it, but not running.
    host.sh("systemctl stop stop-bots-web.service");
    assert_eq!(
        host.unit("stop-bots-web.service", "ActiveState"),
        "inactive"
    );
    assert_eq!(
        host.unit("stop-bots-web.service", "UnitFileState"),
        "enabled"
    );

    // A deploy arrives, exactly as `make deploy` stages it.
    host.sh("cp /usr/local/bin/stop-bots /usr/local/bin/stop-bots.real");
    host.sh("printf '#!/bin/sh\\ntouch /run/deployed-build-ran\\nexec /usr/local/bin/stop-bots.real \"$@\"\\n' > /usr/local/bin/stop-bots.new");
    let out = host.sh("sh /opt/deploy-remote.sh /usr/local/bin/stop-bots stop-bots-web.service");

    assert_eq!(
        host.unit("stop-bots-web.service", "ActiveState"),
        "active",
        "the deploy left the console down. it said:\n{out}\njournal:\n{}",
        host.journal("stop-bots-web.service")
    );
    assert!(
        host.wait_for_file("/run/deployed-build-ran"),
        "the console came back but re-executed the old binary. it said:\n{out}\njournal:\n{}",
        host.journal("stop-bots-web.service")
    );
    assert!(
        out.contains("unit state: active"),
        "the deploy did not report the state it left the unit in:\n{out}"
    );
}

/// The other direction: a host where the console is run by hand has the
/// unit installed but disabled, and a deploy must not start a second copy
/// competing for the port.
#[test]
fn deploying_does_not_start_a_console_nobody_asked_systemd_to_run() {
    if !enabled() {
        return;
    }
    let host = Host::installed("stop-bots-deploy-byhand");
    host.wait_for_console();
    host.put("scripts/deploy-remote.sh", "/opt/deploy-remote.sh");

    host.sh("systemctl disable --now stop-bots-web.service");
    host.sh("cp /usr/local/bin/stop-bots /usr/local/bin/stop-bots.new");
    let out = host.sh("sh /opt/deploy-remote.sh /usr/local/bin/stop-bots stop-bots-web.service");

    assert_eq!(
        host.unit("stop-bots-web.service", "ActiveState"),
        "inactive",
        "a deploy started a service that was deliberately disabled:\n{out}"
    );
}

/// Re-running `install web` must not silently replace an edited unit, and
/// must replace it with `--force`. An operator who tuned a directive and
/// lost it to a routine re-install finds out at the next reboot.
#[test]
fn reinstalling_leaves_an_edited_unit_alone_unless_forced() {
    if !enabled() {
        return;
    }
    let host = Host::installed("stop-bots-reinstall");
    host.wait_for_console();
    host.sh("printf '\\n# operator edit\\n' >> /etc/systemd/system/stop-bots-web.service");

    // A hard refusal, not a warning: re-running the installer is a
    // routine thing to do, and quietly reverting a directive someone
    // tuned would only be discovered at the next reboot.
    let (ok, stdout, stderr) = host.run("stop-bots install web");
    let said = format!("{stdout}{stderr}");
    assert!(
        !ok,
        "a plain re-install over an edited unit should fail:\n{said}"
    );
    assert!(
        host.sh("cat /etc/systemd/system/stop-bots-web.service")
            .contains("# operator edit"),
        "the re-install overwrote the edit. install said:\n{said}"
    );
    assert!(
        said.contains("--force"),
        "it left the edit but never said how to replace it:\n{said}"
    );

    host.sh("stop-bots install web --force");
    assert!(
        !host
            .sh("cat /etc/systemd/system/stop-bots-web.service")
            .contains("# operator edit"),
        "--force did not replace the edited unit"
    );
    assert_eq!(
        host.unit("stop-bots-web.service", "ActiveState"),
        "active",
        "the forced re-install left the service down. journal:\n{}",
        host.journal("stop-bots-web.service")
    );
}

/// The password is generated once and printed once. A second install must
/// not roll it, or every re-install locks the operator out of a console
/// they had bookmarked.
#[test]
fn reinstalling_keeps_the_first_password() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-password");

    let first = host.sh("stop-bots install web");
    let hash = host.password_hash();
    assert!(!hash.is_empty(), "no password hash was stored:\n{first}");

    let second = host.sh("stop-bots install web");

    // The hash is the claim that matters. A quieter second message could
    // just as easily mean the password was rolled and not printed.
    assert_eq!(
        hash,
        host.password_hash(),
        "the stored password hash changed on re-install:\n{second}"
    );
}

/// The database holds the console's password hash, so it must not be
/// readable by anything else on the host.
#[test]
fn the_database_is_not_readable_by_other_users() {
    if !enabled() {
        return;
    }
    let host = Host::installed("stop-bots-perms");

    // The property that matters is reachability, not the mode digits:
    // `install web` chmods the *directory* to 0700 and leaves the file at
    // whatever the umask gave it, so the file is typically 0644 inside a
    // directory nothing else can traverse. Asserting 0600 on the file
    // would fail today for a reason that is not a vulnerability; asserting
    // that another account cannot read it is the real claim.
    host.sh("useradd --create-home --shell /bin/sh snoop");
    let (ok, stdout, stderr) = host.run("su snoop -c 'cat /var/lib/stop-bots/db.sqlite3'");
    assert!(
        !ok,
        "an unprivileged local user read the database holding the console's password hash:\n{stdout}{stderr}"
    );

    let dir_mode = host.sh("stat -c %a /var/lib/stop-bots");
    assert_eq!(
        dir_mode.trim(),
        "700",
        "the state directory is the first thing keeping that file private"
    );
    // And the file's own mode, which is what survives a backup or a `cp`
    // out of that directory.
    let file_mode = host.sh("stat -c %a /var/lib/stop-bots/db.sqlite3");
    assert_eq!(
        file_mode.trim(),
        "600",
        "the database holding the password hash is readable beyond its owner"
    );
}

/// `systemd-analyze verify` is systemd's own parser. A directive this
/// project misspells is accepted silently by `systemctl daemon-reload`
/// and simply does not apply — which is the quietest possible way for
/// hardening to stop hardening.
#[test]
fn systemd_itself_accepts_every_directive_in_the_generated_unit() {
    if !enabled() {
        return;
    }
    let host = Host::installed("stop-bots-verify");

    let (ok, stdout, stderr) =
        host.run("systemd-analyze verify /etc/systemd/system/stop-bots-web.service");
    let output = format!("{stdout}{stderr}");
    assert!(
        ok,
        "systemd-analyze verify rejected the generated unit:\n{output}"
    );
    assert!(
        !output.to_lowercase().contains("unknown"),
        "systemd did not recognise something in the unit:\n{output}"
    );
}

/// Debian's `iptables` is nft-backed, so it reaches the kernel over
/// netlink exactly like `nft` does. The sandbox has to let both through,
/// and the backend that ships on a host this project targets is the one
/// most likely to be reached for.
#[test]
fn the_generated_sandbox_lets_the_iptables_backend_reach_netlink() {
    if !enabled() {
        return;
    }
    let host = Host::installed("stop-bots-iptables-sandbox");

    host.stop_bots("add-firewall-rule --address 203.0.113.11");
    let apply = format!("/usr/local/bin/stop-bots batch --apply --force --no-fetch --backend iptables --root /etc/nginx/sites-enabled --out /etc/stop-bots/firewall.sh --db {HOST_DB}");

    let ran = host.oneshot_under_web_sandbox("probe-iptables", &apply, "");
    assert!(
        ran,
        "the generated sandbox blocks an iptables apply. journal:\n{}",
        host.journal("probe-iptables.service")
    );
    assert!(
        host.sh("iptables -S STOP-BOTS").contains("203.0.113.11"),
        "the apply reported success but the rule is not in the live iptables chain"
    );
}

// ---- the console, as a listening server on a real host ----

/// "Apply everything" from the browser, on a host where both planes are
/// real: NGINX genuinely reloaded, `nft` genuinely loaded.
///
/// This is the end-to-end version of the netlink bug. The console is
/// running under the sandbox `install web` generated, the apply goes
/// through a button rather than a probe unit, and the evidence is a live
/// ruleset and a request that actually gets refused.
#[test]
fn apply_everything_from_the_console_enforces_on_both_planes() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-apply-all");
    let console = host.console();

    host.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    host.seed_bot("badbot", "BadBot");
    host.stop_bots("add-firewall-rule --address 203.0.113.40");

    let flash = console.post("/apply-all", &[]);

    let ruleset = host.sh("nft list ruleset");
    assert!(
        ruleset.contains("203.0.113.40"),
        "the firewall half did not reach the kernel. console said:\n{flash}\nruleset:\n{ruleset}"
    );

    let blocked =
        host.sh("curl -s -o /dev/null -w '%{http_code}' -A 'BadBot/1.0' http://127.0.0.1:8080/");
    assert_eq!(
        blocked.trim(),
        "403",
        "the NGINX half did not take effect — config written but not reloaded"
    );
    let served =
        host.sh("curl -s -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0' http://127.0.0.1:8080/");
    assert_eq!(served.trim(), "200", "everyone else must still be served");
}

/// The Web Access panel writes NGINX config that puts the console behind
/// the very server it is protecting. New codegen, validated by `nginx -t`
/// here for the first time against a config that then has to actually
/// proxy.
///
/// Also pins the documented limitation: the path prefix is read when the
/// router is built, so the console answers on it only after a restart.
#[test]
fn web_access_path_mode_serves_the_console_through_nginx() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-webaccess");
    let console = host.console();
    host.stop_bots("scan-sites --root /etc/nginx/sites-enabled");

    let flash = console.post(
        "/web-access",
        // Every field, including the one this mode does not use: the
        // page's own form posts all four, and the handler deserialises
        // them as a unit.
        &[
            ("mode", "path"),
            ("site", "test.example"),
            ("prefix", "/stop-bots/"),
            ("host", ""),
        ],
    );

    let site = host.sh("cat /etc/nginx/sites-enabled/test-site.conf");
    assert!(
        site.contains("location /stop-bots/"),
        "no console location block was written. console said:\n{flash}\nconfig:\n{site}"
    );
    let (ok, output, err) = host.run("nginx -t");
    assert!(
        ok,
        "the generated console config does not parse:\n{output}{err}"
    );

    // The proxy reaches the console: not a 502, which is what a wrong
    // upstream or a `proxy_pass` trailing slash would give.
    host.sh("systemctl reload nginx");
    let through =
        host.sh("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/stop-bots/");
    assert_ne!(
        through.trim(),
        "502",
        "NGINX could not reach the console it was just pointed at"
    );

    // And after the restart the limitation calls for, the prefixed path
    // really serves the console.
    host.sh("systemctl restart stop-bots-web.service");
    host.wait_for_console_at("/stop-bots");
    let body = host.sh("curl -s -L http://127.0.0.1:8080/stop-bots/");
    assert!(
        body.contains("password"),
        "the console is not being served under its prefix:\n{body}"
    );
}

/// The host allowlist is the DNS-rebinding guard, and `tests/web.rs`
/// checks it against a `Host:` header it sets itself. This checks it
/// against one a real client sent to a real listener.
#[test]
fn the_console_refuses_a_host_header_it_was_not_told_about() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-hosts");
    host.console();

    let loopback = host.sh("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/login");
    assert!(
        loopback.trim().starts_with('2'),
        "loopback should need no configuration, got {loopback}"
    );

    let forged = host.sh(
        "curl -s -o /dev/null -w '%{http_code}' -H 'Host: evil.example' http://127.0.0.1:8787/login",
    );
    // 421 Misdirected Request, which is what the guard returns: the
    // request arrived at a server that does not answer for that name.
    assert_eq!(
        forged.trim(),
        "421",
        "an unlisted Host header reached the console"
    );
}

// ---- NGINX behaviour that needed a real client ----

/// TODO.md has been asking for this one: `set $limit_rate 1` throttles the
/// response body, but how much NGINX writes before the throttle engages on
/// a body this small had never been measured.
///
/// Asserted as "the client is still waiting after five seconds" rather
/// than as a duration: the useful property is that a tarpitted client is
/// held, and a test that pins the exact number would break on an NGINX
/// upgrade without anything being wrong.
#[test]
fn a_tarpitted_client_is_held_while_everyone_else_is_served_at_once() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-tarpit");
    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    server.seed_bot("badbot", "BadBot");
    server.stop_bots("set-block-response --response tarpit");
    server.apply_and_reload();

    let started = std::time::Instant::now();
    let tarpitted = server.status("/", "--max-time 5 -A 'BadBot/1.0'");
    let held = started.elapsed();
    assert_eq!(
        tarpitted, "000",
        "a tarpitted client got a complete response in {held:?}; the throttle \
         is writing the whole body before it engages"
    );
    assert!(
        held >= std::time::Duration::from_secs(4),
        "the connection closed after {held:?} instead of holding the client"
    );

    // The status is the assertion that matters: a tarpitted client cannot
    // produce a 200 inside the same five-second window, it produces the
    // "000" above. So a 200 here *is* "the throttle is scoped to the
    // block", regardless of how long the machine took to say so.
    let started = std::time::Instant::now();
    assert_eq!(
        server.status("/", "--max-time 5 -A 'Mozilla/5.0'"),
        "200",
        "the tarpit is holding everyone, not just blocked clients"
    );
    // A loose sanity bound underneath it, for the same reason the hold
    // above is asserted as ">= 4s" rather than as an exact figure: the
    // useful property is that the two clients are treated differently, and
    // a tighter number measures the machine rather than NGINX. At 2s this
    // failed on a loaded host with nothing wrong — the unblocked client
    // was served, just not quickly, which is not what this test is about.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(4),
        "an unblocked client waited {:?}, as long as a tarpitted one, so the \
         throttle is not scoped to the block",
        started.elapsed()
    );
}

/// Rate limiting is `limit_req`, which NGINX enforces at request time —
/// the one piece of this project that is a runtime component, and the one
/// that cannot be checked by reading generated text.
#[test]
fn rate_limiting_refuses_a_burst_and_then_lets_the_client_back_in() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-ratelimit");
    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    server.stop_bots("set-rate-limit --enabled true --rps 1 --burst 2");
    server.apply_and_reload();

    // Well past rps+burst, as fast as curl can send them.
    let codes = server.sh(
        "for i in $(seq 1 12); do curl -s -o /dev/null -w '%{http_code} ' http://127.0.0.1:8080/; done",
    );
    // 429, not 503: the generated config sets `limit_req_status 429;`,
    // which is the status this project chose for "back off and retry".
    assert!(
        codes.contains("429"),
        "a burst well over the configured rate was never refused: {codes}"
    );
    assert!(
        codes.contains("200"),
        "every request was refused, so the limit is not letting anyone through: {codes}"
    );
}

/// The whole detection loop, with nothing faked at any join: a real client
/// fetches the honeypot from a real NGINX, the detector reads the log
/// NGINX actually wrote, the rule it adds is rendered and loaded into a
/// real ruleset, and the client can no longer reach the server.
///
/// Every one of those steps is tested in isolation elsewhere. None of the
/// joins between them was tested anywhere.
#[test]
fn fetching_the_honeypot_gets_a_real_client_blocked_end_to_end() {
    if !enabled() {
        return;
    }
    let net = Network::create("stop-bots-honeypot-net");
    let server = Server::start_on_network("stop-bots-honeypot", &net);
    let client = Client::start("stop-bots-honeypot-client", &net);

    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    server.stop_bots("set-honeypot-path --path /trap-me");
    server.apply_and_reload();

    assert_eq!(
        client.get("stop-bots-honeypot", ""),
        "200",
        "the client cannot reach the server to begin with"
    );

    // The bait, fetched by the real client through the real server.
    client.get_path("stop-bots-honeypot", "/trap-me", "");

    let found = server.stop_bots("block-honeypot --access-log /var/log/nginx/access.log");
    assert!(
        found.contains(&client.address()),
        "the detector did not find the client in the log NGINX wrote:\n{found}"
    );

    server.stop_bots("render-firewall --backend nftables --out /etc/stop-bots/firewall.nft");
    server.sh("nft -f /etc/stop-bots/firewall.nft");

    assert_eq!(
        client.get("stop-bots-honeypot", "--max-time 5"),
        "000",
        "the client was detected and blocked but can still reach the server. ruleset:\n{}",
        server.sh("nft list ruleset")
    );
}

/// Each request-shape rule, against a request actually shaped that way.
///
/// The generated `if` conditions have golden files, and a golden file
/// cannot tell you whether `$http_accept = ""` is the variable NGINX
/// populates for a request with no `Accept` header. Only a request with no
/// `Accept` header can.
///
/// `http-1x` and `old-tls` are absent on purpose: both only ever land in a
/// TLS `server` block, and there is no certificate here. `http-1x` would
/// also match curl's own HTTP/1.1, so a plain-HTTP check of it could not
/// tell "the rule works" from "everything is blocked".
#[test]
fn each_request_shape_rule_refuses_a_request_actually_shaped_that_way() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-shape");
    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");

    // A request that satisfies every rule, so a 403 below is the rule
    // under test and not a header curl happened not to send.
    let ordinary = "-H 'Accept: text/html' -H 'Accept-Language: en' \
                    -A 'Mozilla/5.0' -H 'Host: test.example'";

    for (rule, offending) in [
        (
            "no-accept",
            "-H 'Accept:' -H 'Accept-Language: en' -A 'Mozilla/5.0'",
        ),
        (
            "no-accept-language",
            "-H 'Accept: text/html' -H 'Accept-Language:' -A 'Mozilla/5.0'",
        ),
        (
            "no-user-agent",
            "-H 'Accept: text/html' -H 'Accept-Language: en' -A ''",
        ),
        (
            "ip-literal-host",
            "-H 'Accept: text/html' -H 'Accept-Language: en' -A 'Mozilla/5.0' -H 'Host: 127.0.0.1'",
        ),
    ] {
        server.stop_bots(&format!(
            "set-site-rule --site test.example --rule {rule} --enabled true"
        ));
        server.apply_and_reload();

        assert_eq!(
            server.status("/", offending),
            "403",
            "{rule} was on and a request matching it was served anyway"
        );
        assert_eq!(
            server.status("/", ordinary),
            "200",
            "{rule} refused an ordinary request too"
        );

        server.stop_bots(&format!(
            "set-site-rule --site test.example --rule {rule} --enabled false"
        ));
        server.apply_and_reload();
        assert_eq!(
            server.status("/", offending),
            "200",
            "{rule} kept refusing after it was switched off"
        );
    }
}

/// A per-site setting has to stop at that site. Two `server` blocks, one
/// rule, and a request that is refused by one and served by the other.
///
/// `tests/cli.rs` already checks that the *text* lands in one file and not
/// the other. What it cannot check is that NGINX agrees — an `if` in the
/// wrong block, or a block written to a file NGINX does not include, looks
/// identical on disk.
#[test]
fn a_per_site_rule_applies_to_that_site_and_not_its_neighbour() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-two-sites");
    server.sh(
        "printf 'server {\n    listen 8081;\n    server_name other.example;\n    \
         root /var/www/test;\n    index index.html;\n    location / { try_files $uri $uri/ =404; }\n}\n' \
         > /etc/nginx/sites-enabled/other-site.conf",
    );
    server.sh("nginx -s reload");
    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");

    let no_ua = "-H 'Accept: text/html' -H 'Accept-Language: en' -A ''";
    assert_eq!(
        server.status("/", no_ua),
        "200",
        "site A serves before the rule"
    );
    assert_eq!(
        server.status_on(8081, "/", no_ua),
        "200",
        "site B serves before the rule"
    );

    server.stop_bots("set-site-rule --site test.example --rule no-user-agent --enabled true");
    server.apply_and_reload();

    assert_eq!(
        server.status("/", no_ua),
        "403",
        "the rule did not take effect on the site it was set for"
    );
    assert_eq!(
        server.status_on(8081, "/", no_ua),
        "200",
        "a rule set for one site is being enforced on its neighbour"
    );
}

/// The probe-path detector, through the same full loop as the honeypot:
/// a real client asks a real NGINX for `/.env`, and the rule that follows
/// really stops it.
///
/// Worth having alongside the honeypot test rather than instead of it —
/// they share the loop but not the matcher, and this one runs against the
/// built-in path list rather than a configured single path.
#[test]
fn probing_for_dotenv_gets_a_real_client_blocked_end_to_end() {
    if !enabled() {
        return;
    }
    let net = Network::create("stop-bots-probe-net");
    let server = Server::start_on_network("stop-bots-probe", &net);
    let client = Client::start("stop-bots-probe-client", &net);

    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    server.apply_and_reload();
    assert_eq!(
        client.get("stop-bots-probe", ""),
        "200",
        "the client cannot reach the server to begin with"
    );

    client.get_path("stop-bots-probe", "/.env", "");
    client.get_path("stop-bots-probe", "/.git/config", "");

    let found = server.stop_bots("block-probe-paths --access-log /var/log/nginx/access.log");
    assert!(
        found.contains(&client.address()),
        "the detector did not find the probing client in NGINX's own log:\n{found}"
    );

    server.stop_bots("render-firewall --backend nftables --out /etc/stop-bots/firewall.nft");
    server.sh("nft -f /etc/stop-bots/firewall.nft");

    assert_eq!(
        client.get("stop-bots-probe", "--max-time 5"),
        "000",
        "the prober was detected and blocked but can still reach the server. ruleset:\n{}",
        server.sh("nft list ruleset")
    );
}

// ---- is this host actually protected? ----

/// **The check the whole `health` module exists for**, against a host
/// genuinely in the state a real server was found in: a pile of generated
/// rules on disk and an empty ruleset in the kernel.
///
/// No amount of asserting on generated text finds this. The script was
/// correct, the database was correct, and the host was open.
#[test]
fn status_reports_generated_rules_that_never_reached_the_kernel() {
    if !enabled() {
        return;
    }
    let host = Host::installed("stop-bots-status-unenforced");

    host.stop_bots("add-firewall-rule --address 203.0.113.60");
    host.stop_bots("render-firewall --backend nftables --out /etc/stop-bots/firewall.nft");

    // Written, never applied — exactly what `render-firewall` promises and
    // exactly the gap nothing used to look at.
    let (ok, out, err) = host.run_uncontended(&format!("stop-bots status --db {HOST_DB}"));
    let said = format!("{out}{err}");
    assert!(
        !ok,
        "a host with nothing enforced should exit non-zero:\n{said}"
    );
    assert!(said.contains("CRITICAL"), "was:\n{said}");
    assert!(
        said.contains("none loaded into the kernel"),
        "the report does not name the problem:\n{said}"
    );

    // Load them, and the same command has to change its mind.
    host.sh("nft -f /etc/stop-bots/firewall.nft");
    let (ok, out, err) = host.run_uncontended(&format!("stop-bots status --db {HOST_DB}"));
    let said = format!("{out}{err}");
    assert!(
        !said.contains("none loaded into the kernel"),
        "the report still says nothing is loaded after loading it:\n{said}"
    );
    assert!(
        ok,
        "with the rules loaded and the console running, nothing should be critical:\n{said}"
    );
}

/// nftables rules live in kernel memory. A host that is protected now and
/// comes back open after a reboot is worth being told about, and the
/// answer comes from systemd rather than from anything this tool wrote.
#[test]
fn status_notices_that_the_ruleset_will_not_survive_a_reboot() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-status-persist");

    let (_, out, err) = host.run_uncontended(&format!("stop-bots status --db {HOST_DB}"));
    let said = format!("{out}{err}");
    assert!(
        said.contains("nftables.service is not enabled"),
        "a host with nftables.service disabled was not told:\n{said}"
    );

    host.sh("systemctl enable nftables.service");
    let (_, out, err) = host.run_uncontended(&format!("stop-bots status --db {HOST_DB}"));
    let said = format!("{out}{err}");
    assert!(
        !said.contains("is not enabled"),
        "enabling the unit did not change the answer:\n{said}"
    );
}

/// Run without root, the probe cannot read the ruleset — and must say so
/// rather than reporting a host it could not look at as healthy.
#[test]
fn status_run_without_root_says_it_could_not_look() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-status-unprivileged");
    host.sh("useradd --create-home --shell /bin/sh checker");
    host.sh("install -d -o checker /home/checker/state");

    let (_, out, err) =
        host.run("su checker -c 'stop-bots status --db /home/checker/state/db.sqlite3'");
    let said = format!("{out}{err}");
    assert!(
        said.contains("UNKNOWN"),
        "an unprivileged run must report what it could not check:\n{said}"
    );
    assert!(
        said.contains("needs root"),
        "it should say why it could not check:\n{said}"
    );
}

/// The internal cron takes the probe, and both dashboards read it back.
/// This asserts the half that crosses a process boundary: the console
/// records a probe, and a separate `status --cached` run sees it.
#[test]
fn the_console_records_a_health_probe_for_the_dashboards_to_read() {
    if !enabled() {
        return;
    }
    let host = Host::installed("stop-bots-status-cached");
    host.wait_for_console();

    // The internal cron runs every due job shortly after start-up, and the
    // health check has never run on a fresh database, so it is due.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut said = String::new();
    while std::time::Instant::now() < deadline {
        let (_, out, err) =
            host.run_uncontended(&format!("stop-bots status --cached --db {HOST_DB}"));
        said = format!("{out}{err}");
        if !said.contains("no health probe has been recorded") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    assert!(
        said.contains("check(s)"),
        "the console never recorded a probe:\n{said}"
    );
    assert!(
        said.contains("from a probe taken"),
        "a cached report should say when it was taken:\n{said}"
    );
}

// ---- the firewall backends, against the real thing ----

/// **The backend/path drift bug.**
///
/// `AppState.firewall_out` was a path fixed at start-up
/// (`/etc/stop-bots/firewall.nft`) while the backend came from a form on
/// every render, so a host set to iptables got `#!/bin/sh` and twelve
/// thousand `iptables -A` lines in a file named for the other backend.
/// Worse, the internal cron hardcoded nftables, so every tick quietly
/// replaced the operator's iptables script with an nftables one *at the
/// same path* — and the next apply ran `sh` over nftables syntax.
///
/// Driven through the console, because the console is where the backend
/// is chosen and where the drift was.
#[test]
fn the_console_writes_each_backend_to_its_own_path_in_its_own_syntax() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-drift");
    let console = host.console();

    host.stop_bots("add-firewall-rule --address 203.0.113.23");

    // A decoy from "the other backend", to catch a render that writes to
    // whichever path it happened to be started with.
    host.sh("printf 'DECOY - must not be overwritten\n' > /etc/stop-bots/firewall.sh");

    console.post("/render-firewall", &[("backend", "nftables"), ("out", "")]);
    let nft = host.sh("cat /etc/stop-bots/firewall.nft");
    assert!(
        nft.contains("203.0.113.23"),
        "the nftables render did not land in firewall.nft:\n{nft}"
    );
    assert!(
        !nft.starts_with("#!/bin/sh"),
        "firewall.nft contains a shell script:\n{nft}"
    );
    // Asserted on syntax rather than on the decoy surviving. The decoy may
    // legitimately be replaced: the console has an internal cron that
    // renders the *stored* backend, every job is due on a fresh database,
    // and since render-on-change it fires again as soon as the rules
    // change — which this test just did. What must never happen is one
    // backend's output landing in the other's file, and a shebang is what
    // tells them apart: the iptables render is a shell script, the
    // nftables one is not.
    let sh_after = host.sh("cat /etc/stop-bots/firewall.sh");
    assert!(
        !sh_after.contains("add rule") && !sh_after.contains("nft "),
        "an nftables render overwrote the iptables script:\n{sh_after}"
    );

    // Now the other way round: switching backend must move the *path*
    // too, not just the syntax.
    host.sh("rm -f /etc/stop-bots/firewall.sh");
    host.sh("printf 'DECOY - must not be overwritten\n' > /etc/stop-bots/firewall.nft");
    console.post("/render-firewall", &[("backend", "iptables"), ("out", "")]);

    let sh = host.sh("cat /etc/stop-bots/firewall.sh");
    assert!(
        sh.starts_with("#!/bin/sh"),
        "the iptables render is not a shell script:\n{sh}"
    );
    assert!(
        sh.contains("iptables") && sh.contains("203.0.113.23"),
        "the iptables render has no rule in it:\n{sh}"
    );
    // Same again, and this is the half that caught a real cron race: by
    // now the stored backend is iptables, so the cron renders
    // `firewall.sh` and leaves `firewall.nft` alone — but a tick landing
    // between the decoy and this read would have replaced it with a
    // perfectly legitimate nftables render, and the old assertion called
    // that the bug.
    let nft_after = host.sh("cat /etc/stop-bots/firewall.nft");
    assert!(
        !nft_after.starts_with("#!/bin/sh"),
        "an iptables render overwrote the nftables script — the bug exactly:\n{nft_after}"
    );
}

/// `batch` is what a real crontab runs, and it used to carry a `nftables`
/// default that no host setting could override — so an operator who chose
/// iptables in the console got an nftables script from every cron run, at
/// the other path, and ended up with two files in two syntaxes one of
/// which was always stale.
///
/// An explicit `--backend` still wins. Without one, the host's own setting
/// decides.
#[test]
fn batch_follows_the_stored_backend_unless_the_flag_says_otherwise() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-batch-backend");
    let console = host.console();

    host.stop_bots("add-firewall-rule --address 203.0.113.50");

    // The console is where the backend is chosen, so choose it there.
    console.post("/render-firewall", &[("backend", "iptables"), ("out", "")]);
    host.sh("rm -f /etc/stop-bots/firewall.sh /etc/stop-bots/firewall.nft");

    // No --backend: the stored choice has to decide both syntax and path.
    host.stop_bots("batch --no-fetch --force --root /etc/nginx/sites-enabled");
    assert!(
        !host.run("test -e /etc/stop-bots/firewall.nft").0,
        "a crontab-shaped run wrote an nftables script to a host set to iptables"
    );
    let written = host.sh("cat /etc/stop-bots/firewall.sh");
    assert!(
        written.starts_with("#!/bin/sh") && written.contains("203.0.113.50"),
        "the stored backend did not decide what batch generated:\n{written}"
    );

    // An explicit flag still overrides it, in both syntax and path.
    host.stop_bots("batch --no-fetch --force --backend nftables --root /etc/nginx/sites-enabled");
    let forced = host.sh("cat /etc/stop-bots/firewall.nft");
    assert!(
        !forced.starts_with("#!/bin/sh") && forced.contains("203.0.113.50"),
        "an explicit --backend did not win:\n{forced}"
    );
}

/// The iptables backend has been rendered and golden-tested for a long
/// time and never once executed. `iptables.rs` is at 100% line coverage,
/// which says only that every line ran, not that the script it produces
/// loads.
#[test]
fn generated_iptables_scripts_load_into_real_iptables() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-iptables-load");
    server.stop_bots("add-firewall-rule --address 203.0.113.30");
    server.stop_bots("add-firewall-rule --address 203.0.113.0/24");
    server.stop_bots("render-firewall --backend iptables --out /etc/stop-bots/firewall.sh");

    server.sh("sh /etc/stop-bots/firewall.sh");

    let live = server.sh("iptables -S STOP-BOTS");
    assert!(
        live.contains("203.0.113.30"),
        "single address missing:\n{live}"
    );
    assert!(
        live.contains("203.0.113.0/24"),
        "CIDR range missing:\n{live}"
    );
}

/// Applying the same script twice must leave one chain with one copy of
/// each rule. The generated script flushes `STOP-BOTS` before filling it,
/// and "it flushes" is a claim about a shell script nobody had run twice.
#[test]
fn re_applying_the_iptables_script_does_not_double_the_rules() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-iptables-idempotent");
    server.stop_bots("add-firewall-rule --address 203.0.113.31");
    server.stop_bots("render-firewall --backend iptables --out /etc/stop-bots/firewall.sh");

    server.sh("sh /etc/stop-bots/firewall.sh");
    let once = server.sh("iptables -S STOP-BOTS");
    server.sh("sh /etc/stop-bots/firewall.sh");
    let twice = server.sh("iptables -S STOP-BOTS");

    assert_eq!(
        once, twice,
        "a second run changed the chain, so it is accumulating rules"
    );
    assert_eq!(
        twice.matches("203.0.113.31").count(),
        1,
        "the rule is in the chain more than once:\n{twice}"
    );
}

/// Allowlist mode turns the host into default-deny once the script runs.
/// That is the highest-stakes thing this project can generate, and it had
/// a golden file and no execution.
#[test]
fn allowlist_mode_really_drops_everything_outside_the_selection() {
    if !enabled() {
        return;
    }
    let net = Network::create("stop-bots-allowlist-net");
    let server = Server::start_on_network("stop-bots-allowlist", &net);
    let client = Client::start("stop-bots-allowlist-client", &net);

    assert_eq!(
        client.get("stop-bots-allowlist", ""),
        "200",
        "the client cannot reach the server before any rules exist"
    );

    // A country whose ranges cover nothing the client is in, selected in
    // allowlist mode: everything else must be dropped.
    server.sh("printf '192.0.2.0/24\n' > /tmp/zone.zone");
    server.stop_bots("update-country-ranges --country nl --source /tmp/zone.zone");
    server.stop_bots("add-country --country nl");
    server.stop_bots("set-geo-mode --mode allowlist");
    server.stop_bots("render-firewall --backend nftables --out /etc/stop-bots/firewall.nft");
    server.sh("nft -f /etc/stop-bots/firewall.nft");

    assert_eq!(
        client.get("stop-bots-allowlist", "--max-time 5"),
        "000",
        "allowlist mode let an address outside the selection through. ruleset:\n{}",
        server.sh("nft list ruleset")
    );
    // And the host has not cut off its own loopback, which is the way
    // default-deny goes wrong.
    assert_eq!(
        server.status("/", ""),
        "200",
        "allowlist mode blocked loopback"
    );
}

/// `nftables`' `inet` family covers IPv4 and IPv6 in one table, which is
/// the stated reason `iptables::render` may skip IPv6 rules. Stated, and
/// never checked against an actual IPv6 packet.
#[test]
fn an_ipv6_rule_really_drops_ipv6_traffic() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-ipv6");
    server.sh("ip -6 addr add 2001:db8::1/64 dev lo || true");
    server.stop_bots("add-firewall-rule --address 2001:db8::/64");
    server.stop_bots("render-firewall --backend nftables --out /etc/stop-bots/firewall.nft");
    server.sh("nft -f /etc/stop-bots/firewall.nft");

    let ruleset = server.sh("nft list ruleset");
    assert!(
        ruleset.contains("2001:db8::/64"),
        "the IPv6 rule is not in the live ruleset:\n{ruleset}"
    );
    let (_, code, _) = server
        .run("curl -s -o /dev/null -w '%{http_code}' --max-time 5 -g 'http://[2001:db8::1]:8080/'");
    assert_eq!(
        code.trim(),
        "000",
        "an address inside a dropped IPv6 range was still served"
    );
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
