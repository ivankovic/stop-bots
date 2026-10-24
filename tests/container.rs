/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, version 3 of the License.
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
//! **They do not run by default.** They need a container runtime, take
//! tens of seconds, and would break `cargo test` on any machine without
//! one. Set `STOP_BOTS_CONTAINER_TESTS=1` to enable them; `make
//! integration-test` does that for you. CI runs them as their own job.
//!
//! ## Which runtime
//!
//! `docker` unless `STOP_BOTS_CONTAINER_RUNTIME` says otherwise, which is
//! what CI uses. Setting it to `podman` runs the same suite rootless —
//! see [`runtime()`] for why that option is here, and [`Host::boot`] for
//! the one place the two need different flags. Both are exercised; the
//! systemd assertions below were confirmed to still fail when their
//! directive is removed under each.
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
//! the reason three separate bugs reached a live server, each a property
//! of a generated unit under a real service manager that no amount of
//! asserting on the unit's *text* finds — the text was what everyone had
//! already read. The units those bugs were in belonged to the web console,
//! since removed; the firewall's boot unit, the cron file and the upgrade
//! from a release that had the console are what run here now.
//!
//! Tests of the boot unit's sandbox derive their probes from the unit
//! `install firewall` actually wrote (see [`Host::oneshot_under_sandbox_of`])
//! rather than from a hand-written copy, and each carries a negative
//! control that puts back what the sandbox takes away and asserts the
//! escape works. Without that control, a container where the sandbox
//! silently did not apply would pass every one of them.
//!
//! ## And a stranger's host
//!
//! `Dockerfile.stranger` is a fresh Debian 12 or Ubuntu 24.04, with NGINX
//! or Apache, and nothing of ours on it, for
//! [`a_stranger_follows_the_quick_start`]: the README's
//! quick start from `apt install` of the `.deb` to `uninstall all`. It
//! needs a package, named by `STOP_BOTS_STRANGER_DEB`, and skips without
//! one; `make stranger-test` builds one and runs it.
//!
//! ## And two hosts nobody here runs
//!
//! `Dockerfile.rhel` is AlmaLinux 10's `httpd`, for RHEL's `/etc/httpd`
//! tree. `Dockerfile.upgrade` is the [`Host`] image with the released 0.1.1
//! binary beside the one under test, so the upgrade tests start from what
//! 0.1.1 actually left on a host.
//!
//! ## And NPMplus, in its own image
//!
//! [`Npmplus`] runs NPMplus's released image rather than one of these, and
//! stop-bots outside it, on the machine running the tests, as an operator
//! runs it: see the section's own comment.

use std::process::Command;

/// Skips the test unless container tests are switched on. Returns whether
/// to proceed, and says why not — a silently skipped test is how a whole
/// suite quietly stops running.
fn enabled() -> bool {
    if std::env::var_os("STOP_BOTS_CONTAINER_TESTS").is_some() {
        return true;
    }
    stop_bots::say_err!(
        "skipping: container tests are off. Set STOP_BOTS_CONTAINER_TESTS=1 \
         (or run `make integration-test`) to enable them."
    );
    false
}

/// The container runtime to drive, from `STOP_BOTS_CONTAINER_RUNTIME`.
///
/// Defaults to `docker`, which is what CI has and what this suite was
/// written against. The override exists because the daemon Docker talks
/// to runs as root: on a machine that also hosts unrelated root-owned
/// containers, joining the `docker` group to run these tests hands over
/// every one of those containers too, since the socket has no notion of
/// per-container permission. Rootless Podman has no daemon and its own
/// per-user storage, so the suite can run without that trade.
///
/// Anything CLI-compatible works; `podman` is the one that is actually
/// exercised. Read once — a test run must not straddle two runtimes,
/// which is the sort of thing an env var changed mid-run would do.
fn runtime() -> &'static str {
    static RUNTIME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| {
        std::env::var("STOP_BOTS_CONTAINER_RUNTIME").unwrap_or_else(|_| "docker".to_string())
    })
}

/// Whether the runtime is Podman, which needs different flags to boot
/// systemd — see [`Host::boot`].
fn runtime_is_podman() -> bool {
    runtime().contains("podman")
}

/// Appended to every image tag and every container and network name, from
/// `STOP_BOTS_CONTAINER_SUFFIX`. Unset, the names are what they always
/// were.
///
/// Two checkouts running this suite at once otherwise share one image tag
/// and one set of container names: the second build replaces the image
/// under the first run, which then tests the other checkout's binary, and
/// each run's `rm -f` removes the other's containers. A suffix per
/// checkout keeps them apart.
fn suffix() -> &'static str {
    static SUFFIX: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SUFFIX.get_or_init(|| std::env::var("STOP_BOTS_CONTAINER_SUFFIX").unwrap_or_default())
}

/// `name`, with [`suffix`] if there is one.
fn scoped(name: &str) -> String {
    match suffix() {
        "" => name.to_string(),
        suffix => format!("{name}-{suffix}"),
    }
}

/// The image tag, which is `latest` unless [`suffix`] says otherwise.
fn tagged(image: &str) -> String {
    match suffix() {
        "" => format!("{image}:latest"),
        suffix => format!("{image}:{suffix}"),
    }
}

fn image() -> String {
    tagged("stop-bots-test")
}

/// The image with a real init — see `Dockerfile.host` and [`Host`].
fn host_image() -> String {
    tagged("stop-bots-host")
}

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
    ONCE.call_once(|| with_build_lock(|| build_unless_current(&image(), build_image_now)));
}

/// Builds `image` with `build` unless this run already built it from the
/// same binary and Dockerfiles, which a marker in the target directory
/// records.
///
/// Under nextest every test process gets here, one after another through
/// [`with_build_lock`]. Rebuilding each time is all cache hits, but on a
/// loaded machine a cached rebuild still costs seconds, and fifty-eight of
/// them in a row spent the first tests' whole time budget waiting for the
/// lock. The marker's key is the binary's and the build context's sizes
/// and mtimes, so a rebuilt binary is never tested through a stale image,
/// and the image has to still exist.
fn build_unless_current(image: &str, build: impl FnOnce()) {
    let marker = format!(
        "{}/container-image-{}.built",
        env!("CARGO_TARGET_TMPDIR"),
        image.replace([':', '/'], "_")
    );
    let key = build_key();
    let exists = Command::new(runtime())
        .args(["image", "inspect", image])
        .output()
        .is_ok_and(|out| out.status.success());
    if exists && std::fs::read_to_string(&marker).ok().as_deref() == Some(key.as_str()) {
        return;
    }
    build();
    std::fs::write(&marker, key).expect("failed to record the image build");
}

/// What an image is built from, as sizes and mtimes: the binary under test
/// and everything in the build context but the staged copy of it.
fn build_key() -> String {
    let stamp = |path: &std::path::Path| {
        let meta = std::fs::metadata(path).expect("a build input is missing");
        format!(
            "{} {} {:?}\n",
            path.display(),
            meta.len(),
            meta.modified().ok()
        )
    };
    let mut key = stamp(std::path::Path::new(env!("CARGO_BIN_EXE_stop-bots")));
    let ctx = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/container");
    let mut inputs: Vec<_> = std::fs::read_dir(&ctx)
        .expect("the build context is missing")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.file_name().is_some_and(|name| name != "stop-bots"))
        .collect();
    inputs.sort();
    for path in inputs {
        key.push_str(&stamp(&path));
    }
    key
}

/// Runs `f` holding an exclusive `flock` shared by every process of this
/// checkout's test run.
///
/// The `Once`s here guard threads, and `cargo test` runs every test as a
/// thread of one process. `cargo nextest` — which CI uses for this suite,
/// for its retries — runs each test as a process of its own, where a
/// `Once` guards nothing: every test would stage the binary and build the
/// images at once, and one process's copy would truncate the binary under
/// another's build. That is the race `stage_binary` describes, back through
/// a door the `Once`s cannot close. Staging and building under this lock
/// closes it for both runners. A rebuild after the first is all cache hits,
/// so the cost is a second or so per test process.
///
/// In the target directory, so two checkouts (which already build under
/// different `STOP_BOTS_CONTAINER_SUFFIX`es) do not wait for each other.
fn with_build_lock<T>(f: impl FnOnce() -> T) -> T {
    use std::os::fd::AsRawFd;
    let path = concat!(env!("CARGO_TARGET_TMPDIR"), "/container-build.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .expect("failed to open the image build lock");
    // SAFETY: a valid descriptor, owned by `file` until it drops below.
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    assert_eq!(locked, 0, "failed to lock {path}");
    let result = f();
    drop(file);
    result
}

/// The same, for the systemd image. A separate `Once` so a run that only
/// touches one of the two images only builds that one.
fn build_host_image() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        with_build_lock(|| build_unless_current(&host_image(), build_host_image_now))
    });
}

fn build_host_image_now() {
    let ctx = stage_binary();
    let out = Command::new(runtime())
        .args([
            "build",
            "-q",
            "-f",
            &format!("{ctx}/Dockerfile.host"),
            "-t",
            &host_image(),
            &ctx,
        ])
        .output()
        .expect("failed to run the image build");
    assert!(
        out.status.success(),
        "{} build (host image) failed:\n{}",
        runtime(),
        String::from_utf8_lossy(&out.stderr)
    );
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
    let out = Command::new(runtime())
        .args(["build", "-q", "-t", &image(), &ctx])
        .output()
        .expect("failed to run the image build");
    assert!(
        out.status.success(),
        "{} build failed:\n{}",
        runtime(),
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
/// **Not the runtime's default.** Both hand out RFC1918 addresses, and every
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
/// Carved into /28s because tests run in parallel and both runtimes
/// refuse two networks whose pools overlap. Sixteen is far more than the handful of
/// networked tests here, and each gets thirteen usable addresses.
fn test_subnet(index: usize) -> String {
    format!("198.51.100.{}/28", (index % 16) * 16)
}

/// The same slicing inside 172.31.255.0/24: RFC1918, like the address a
/// Docker bridge hands a container. For the tests about a container
/// reaching a service on its own host, where being private is the point.
fn private_test_subnet(index: usize) -> String {
    format!("172.31.255.{}/28", (index % 16) * 16)
}

impl Network {
    fn create(name: &str) -> Network {
        Network::create_in(name, test_subnet, None)
    }

    fn create_private(name: &str) -> Network {
        Network::create_in(name, private_test_subnet, None)
    }

    /// [`Network::create`] with IPv6 as well, from the documentation
    /// prefix (RFC 3849) for the reason [`test_subnet`] uses TEST-NET-2:
    /// not private, and routed nowhere.
    fn create_dual_stack(name: &str) -> Network {
        Network::create_in(
            name,
            test_subnet,
            Some(|index| format!("2001:db8:{:x}::/64", index % 16)),
        )
    }

    fn create_in(
        name: &str,
        subnet_for: fn(usize) -> String,
        ipv6_subnet_for: Option<fn(usize) -> String>,
    ) -> Network {
        let name = &scoped(name);
        // A test killed at its time limit never ran its `Drop`s, so its
        // containers are still attached and `network rm` refuses. Under
        // nextest's retries the next try is exactly that case: it then
        // failed with "network already exists" on every slice below.
        // Podman's `-f` removes the attached containers too. Docker's only
        // ignores a missing network, so there the leftovers are found and
        // removed, but only when the plain removal was refused: listing
        // containers by network is slow with many on the host.
        let removed = Command::new(runtime())
            .args(["network", "rm", "-f", name])
            .output();
        let refused = removed
            .is_ok_and(|out| String::from_utf8_lossy(&out.stderr).contains("active endpoints"));
        if refused {
            if let Ok(out) = Command::new(runtime())
                .args(["ps", "-aq", "--filter", &format!("network={name}")])
                .output()
            {
                for id in String::from_utf8_lossy(&out.stdout).split_whitespace() {
                    let _ = Command::new(runtime()).args(["rm", "-f", id]).output();
                }
            }
            let _ = Command::new(runtime())
                .args(["network", "rm", name])
                .output();
        }

        // Retry across slices rather than pick one and hope: a network
        // left behind by an aborted run still holds its pool, and the
        // failure ("Pool overlaps with other one on this address space")
        // names neither which network nor which test.
        //
        // Offset by the process id, because under nextest every test is a
        // process of its own with its own `NEXT` starting at zero, and
        // they would all try the same slice first.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let mut last = String::new();
        for _ in 0..16 {
            let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + std::process::id() as usize;
            let mut args = vec![
                "network".to_string(),
                "create".to_string(),
                "--subnet".to_string(),
                subnet_for(index),
            ];
            if let Some(v6) = ipv6_subnet_for {
                args.extend(["--ipv6".to_string(), "--subnet".to_string(), v6(index)]);
            }
            args.push(name.to_string());
            let out = Command::new(runtime())
                .args(&args)
                .output()
                .expect("failed to create a container network");
            if out.status.success() {
                return Network {
                    name: name.to_string(),
                };
            }
            last = String::from_utf8_lossy(&out.stderr).to_string();
        }
        panic!(
            "{} network create failed for every subnet slice:\n{last}",
            runtime()
        );
    }
}

/// Runs a shell command inside a container, returning (exit status
/// success, stdout, stderr). The one `docker exec` every assertion in this
/// file flows through.
fn exec_in(container: &str, cmd: &str) -> (bool, String, String) {
    let out = Command::new(runtime())
        .args(["exec", container, "sh", "-c", cmd])
        .output()
        .expect("failed to exec in the container");
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

/// A container's address on its network: `field` is `IPAddress` or
/// `GlobalIPv6Address`, as `inspect` names them.
fn address_of(container: &str, field: &str) -> String {
    let out = Command::new(runtime())
        .args([
            "inspect",
            "-f",
            &format!("{{{{range .NetworkSettings.Networks}}}}{{{{.{field}}}}}{{{{end}}}}"),
            container,
        ])
        .output()
        .expect("failed to inspect a container");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `docker rm -f`, for the `Drop` impls. Errors are ignored: a container
/// that is already gone is the outcome wanted.
fn remove_container(name: &str) {
    let _ = Command::new(runtime()).args(["rm", "-f", name]).output();
}

impl Drop for Network {
    fn drop(&mut self) {
        let _ = Command::new(runtime())
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
        let name = &scoped(name);
        let _ = Command::new(runtime()).args(["rm", "-f", name]).output();
        let out = Command::new(runtime())
            .args([
                "run",
                "-d",
                "--name",
                name,
                "--network",
                &net.name,
                &image(),
            ])
            .output()
            .expect("failed to start the client container");
        assert!(
            out.status.success(),
            "{} run (client) failed:\n{}",
            runtime(),
            String::from_utf8_lossy(&out.stderr)
        );
        Client {
            name: name.to_string(),
        }
    }

    /// This container's address on the network, as the server will see it.
    fn address(&self) -> String {
        address_of(&self.name, "IPAddress")
    }

    /// Its IPv6 address, on a [`Network::create_dual_stack`] network.
    fn address_v6(&self) -> String {
        address_of(&self.name, "GlobalIPv6Address")
    }

    /// Fetches `path` from `host` and returns the status code.
    fn get_path(&self, host: &str, path: &str, extra: &str) -> String {
        let out = Command::new(runtime())
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
        let out = Command::new(runtime())
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
        let name = &scoped(name);
        // Leftover from a previous aborted run.
        let _ = Command::new(runtime()).args(["rm", "-f", name]).output();

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
        args.push(image());
        let out = Command::new(runtime())
            .args(&args)
            .output()
            .expect("failed to start the container");
        assert!(
            out.status.success(),
            "{} run failed:\n{}",
            runtime(),
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

    /// Whether the loaded `inet stop_bots` table has `element` in `set` —
    /// asked of the kernel with `nft get element`, which for an interval
    /// set also answers for an address inside a listed range.
    fn in_set(&self, set: &str, element: &str) -> bool {
        self.run(&format!(
            "nft get element inet stop_bots {set} '{{ {element} }}'"
        ))
        .0
    }

    /// Renders the firewall for `backend` into `/tmp/fw` and loads it the
    /// way the apply does. `--force` because a container has no SSH log.
    fn render_and_load(&self, backend: &str) {
        self.stop_bots(&format!(
            "render-firewall --backend {backend} --out /tmp/fw --force"
        ));
        let load = if backend == "nftables" {
            "nft -f /tmp/fw"
        } else {
            "sh /tmp/fw"
        };
        self.sh(load);
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

/// Where the host's database is: what `install cron` points `tick` at.
const HOST_DB: &str = "/var/lib/stop-bots/db.sqlite3";

impl Host {
    /// A booted host with NGINX running — every test here wants that
    /// much, so it is not a line they each repeat.
    fn start(name: &str) -> Host {
        let host = Host::boot(name);
        host.sh("systemctl start nginx");
        host
    }

    /// Runs `stop-bots` on the host against the host's database.
    fn stop_bots(&self, args: &str) -> String {
        self.sh(&format!("stop-bots {args} --db {HOST_DB}"))
    }

    fn boot(name: &str) -> Host {
        build_host_image();
        Host::boot_image(name, &host_image(), None)
    }

    /// Boots `image` as a host, on `network` if one is given. Every
    /// systemd image here boots the same way; only what is in it differs.
    fn boot_image(name: &str, image: &str, network: Option<&Network>) -> Host {
        let name = &scoped(name);
        // Leftover from a previous aborted run.
        let _ = Command::new(runtime()).args(["rm", "-f", name]).output();

        let mut args = vec![
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            name.to_string(),
            // systemd needs to mount things: every `Protect*` and
            // `Private*` directive in the generated unit is a mount
            // namespace, and without this they are silently not
            // applied — which would make every assertion below pass
            // for the wrong reason.
            "--cap-add=SYS_ADMIN".to_string(),
            // `nft` and `iptables` manipulate the container's own
            // netfilter tables, same as `Server`.
            "--cap-add=NET_ADMIN".to_string(),
            // The outer seccomp profile blocks syscalls systemd needs to
            // boot at all. Turning it off does *not* weaken what is under
            // test: `RestrictAddressFamilies` is enforced by a seccomp
            // filter systemd installs itself, inside the unit, and it was
            // verified to still refuse AF_NETLINK with this off — under
            // both runtimes.
            "--security-opt".to_string(),
            "seccomp=unconfined".to_string(),
        ];

        // How the two runtimes are told to host an init, and the one
        // place in this file where they genuinely differ.
        //
        // Podman knows what a systemd container needs and sets it up
        // itself: `--systemd=always` gives the container a writable
        // cgroup hierarchy of its own plus the tmpfs mounts on /run and
        // /run/lock. Docker has no such flag, so the same conditions have
        // to be assembled by hand — and bind-mounting the host's
        // /sys/fs/cgroup read-write, which is what that takes, is
        // precisely the kind of access rootless Podman exists to avoid.
        // Asking for it there fails outright rather than degrading.
        if runtime_is_podman() {
            args.push("--systemd=always".to_string());
        } else {
            // AppArmor confines the Docker daemon's containers; there is
            // no equivalent profile applied in the rootless case.
            args.push("--security-opt".to_string());
            args.push("apparmor=unconfined".to_string());
            args.push("--cgroupns=host".to_string());
            args.push("-v".to_string());
            args.push("/sys/fs/cgroup:/sys/fs/cgroup:rw".to_string());
            args.push("--tmpfs".to_string());
            args.push("/run".to_string());
            args.push("--tmpfs".to_string());
            args.push("/run/lock".to_string());
        }
        if let Some(network) = network {
            args.push("--network".to_string());
            args.push(network.name.clone());
        }
        args.push(image.to_string());

        let out = Command::new(runtime())
            .args(&args)
            .output()
            .expect("failed to start the host container");
        assert!(
            out.status.success(),
            "{} run (host) failed:\n{}",
            runtime(),
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

    /// [`Self::run`], retried while SQLite says the database is locked.
    ///
    /// A CLI command and `tick` from cron are two processes sharing one
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
        let out = Command::new(runtime())
            .args(["cp", local, &format!("{}:{remote}", self.name)])
            .output()
            .expect("failed to copy into the container");
        assert!(
            out.status.success(),
            "{} cp {local} failed:\n{}",
            runtime(),
            String::from_utf8_lossy(&out.stderr)
        );
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

    /// Runs `command` as a oneshot unit carrying the sandbox of `unit`, a
    /// unit `install` wrote, every directive but `ExecStart` and `Type`
    /// copied from it, and returns whether it succeeded. `mangle` edits the
    /// copy first, so a test can take a directive away.
    ///
    /// Its `Condition*` lines go too: the firewall unit's
    /// `ConditionPathExists` would otherwise skip a probe whose script is
    /// not there, and systemd counts a skipped start as a successful one.
    ///
    /// The command goes into the unit from a file (`sed`'s `r`) rather
    /// than through a substitution, so it may hold `&`, `|` and quotes;
    /// systemd still splits it, so `$` has to be `$$`.
    fn oneshot_under_sandbox_of(
        &self,
        unit: &str,
        probe: &str,
        command: &str,
        mangle: &str,
    ) -> bool {
        self.sh(&format!(
            "cat > /run/{probe}.exec <<'STOP_BOTS_PROBE'\nExecStart={command}\nSTOP_BOTS_PROBE"
        ));
        self.sh(&format!(
            "set -e\n\
             sed -e '/^ExecStart=/{{r /run/{probe}.exec' -e 'd;}}' \
                 -e 's|^Type=.*|Type=oneshot|' \
                 -e 's|^Restart=.*||' \
                 -e '/^Condition/d' \
                 /etc/systemd/system/{unit} {mangle} \
                 > /etc/systemd/system/{probe}.service\n\
             systemctl daemon-reload",
        ));
        self.try_start(&format!("{probe}.service"))
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        remove_container(&self.name);
    }
}

// ---- what `install` writes, on a real host ----

/// **The schedule `install cron` writes runs, as cron runs it.** The file
/// is root's and 0644, which cron insists on, and its one line, run by
/// `/bin/sh` with nothing but the file's own `PATH` — as cron runs it —
/// reads the access log and blocks the prober in it.
#[test]
fn the_installed_cron_line_runs_the_schedule() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-cron");
    host.sh("touch /var/log/auth.log");
    host.stop_bots("set-log-paths --ssh-log /var/log/auth.log");
    host.sh(
        "now=$(date +'%d/%b/%Y:%H:%M:%S %z') && \
         echo \"203.0.113.77 - - [$now] \\\"GET /.env HTTP/1.1\\\" 404 0 \\\"-\\\" \\\"curl/8\\\"\" \
           >> /var/log/nginx/access.log",
    );
    host.sh("stop-bots install cron");

    assert_eq!(
        host.sh("stat -c '%U %a' /etc/cron.d/stop-bots").trim(),
        "root 644",
        "cron skips a file in /etc/cron.d that is not root's alone"
    );
    let file = host.sh("cat /etc/cron.d/stop-bots");
    let line = file
        .lines()
        .find(|line| line.starts_with("* * * * * root "))
        .unwrap_or_else(|| panic!("no schedule line in:\n{file}"));
    let command = line.trim_start_matches("* * * * * root ");
    let path = file
        .lines()
        .find_map(|line| line.strip_prefix("PATH="))
        .expect("the file sets PATH, as cron's own is minimal");
    host.sh(&format!(
        "env -i PATH={path} /bin/sh -c {}",
        sh_quoted(command)
    ));

    let rules = host
        .run_uncontended(&format!("stop-bots list-firewall-rules --db {HOST_DB}"))
        .1;
    assert!(
        rules.contains("203.0.113.77"),
        "the cron line did not block the prober:\n{rules}"
    );
}

/// `uninstall` puts the host back as it was: every site file byte for
/// byte, no generated `conf.d` file, no nft table, no iptables chain, no
/// unit and no cron file — against the real systemd, NGINX, nft and
/// iptables.
///
/// Both firewall backends are applied, because a host that switched
/// backends has both, and `uninstall` removes whichever exist.
#[test]
fn uninstall_puts_the_host_back_as_it_was() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-uninstall");
    // Everything `uninstall` promises to put back, read the same way
    // before and after. Not /etc/stop-bots: this image creates it empty,
    // and `uninstall` removes it once it is.
    //
    // Nor the nft tables `iptables` itself owns. Debian's `iptables` is
    // iptables-nft, which creates `ip filter` the first time a rule is
    // added and never removes it; what is in it is exactly what
    // `iptables -S` lists, compared here too. Deleting that table would
    // delete ufw's and Docker's rules along with ours.
    let state = || {
        host.sh("set -e\n\
             find /etc/nginx -type f | sort | xargs sha256sum\n\
             echo '-- nft'\n\
             nft list tables | grep -v -e '^table ip filter$' -e '^table ip6 filter$' || true\n\
             echo '-- iptables'; iptables -S; ip6tables -S\n\
             echo '-- units'; find /etc/systemd/system -name 'stop-bots*' | sort\n\
             systemctl list-unit-files 'stop-bots*' --no-legend | sort\n\
             echo '-- cron'; find /etc/cron.d -name 'stop-bots*' | sort")
    };
    let before = state();

    host.sh("stop-bots install cron");
    host.sh("stop-bots install firewall");
    host.seed_bot("badbot", "BadBot");
    host.stop_bots("set-rate-limit --enabled true");
    host.stop_bots("add-trusted --address 192.0.2.77");
    host.stop_bots("apply-blocks");
    host.stop_bots("add-firewall-rule --address 203.0.113.60");
    host.stop_bots("render-firewall --backend nftables --out /etc/stop-bots/firewall.nft");
    host.sh("nft -f /etc/stop-bots/firewall.nft");
    host.stop_bots("render-firewall --backend iptables --out /etc/stop-bots/firewall.sh");
    host.sh("sh /etc/stop-bots/firewall.sh");
    let applied = state();
    for (what, needle) in [
        ("the site block", "stop-bots-limits.conf"),
        ("the nft table", "table inet stop_bots"),
        ("the iptables chain", "-N STOP-BOTS"),
        ("the cron file", "/etc/cron.d/stop-bots"),
        ("the firewall unit", "stop-bots-firewall.service"),
    ] {
        assert!(
            applied.contains(needle),
            "{what} was never there:\n{applied}"
        );
    }

    let (ok, stdout, stderr) = host.run("stop-bots uninstall");

    let said = format!("{stdout}{stderr}");
    assert!(ok, "uninstall failed:\n{said}");
    assert_eq!(
        state(),
        before,
        "the host is not as it was. uninstall said:\n{said}"
    );
    // Only the host settings, which, like the database, stay unless
    // `--purge`.
    assert_eq!(
        host.sh("find /etc/stop-bots -type f 2>/dev/null || true")
            .trim(),
        "/etc/stop-bots/host.conf",
        "{said}"
    );
    let (valid, out, err) = host.run("nginx -t");
    assert!(
        valid,
        "NGINX does not load what uninstall left:\n{out}{err}"
    );
    // Polled: a reload is asynchronous, and an old worker can still answer.
    let mut served = String::new();
    for _ in 0..50 {
        served = host
            .sh("curl -s -o /dev/null -w '%{http_code}' -A 'BadBot/1.0' http://127.0.0.1:8080/");
        if served.trim() == "200" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(served.trim(), "200", "the running NGINX still blocks");
    assert!(
        host.run(&format!("test -f {HOST_DB}")).0 && said.contains(HOST_DB),
        "the database must be kept, and the output must say where:\n{said}"
    );
}

/// The boot unit runs a script as root. Under its sandbox that script can
/// load rules and nothing else: it cannot write to `/etc/cron.d`, and it
/// cannot ask systemd to.
///
/// The control proves the escape is real: the same sandbox with `AF_UNIX`
/// put back lets `systemd-run` write where the sandbox itself cannot.
#[test]
fn the_boot_unit_can_load_rules_but_not_write_or_reach_systemd() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-boot-sandbox");
    host.stop_bots("add-firewall-rule --address 203.0.113.90");
    host.stop_bots("render-firewall --apply --force");
    host.sh("stop-bots install firewall");
    host.sh("mkdir -p /etc/cron.d && systemctl start dbus.socket dbus.service");
    let unit = "stop-bots-firewall.service";
    let escape = "/usr/bin/systemd-run --wait -q /usr/bin/touch /etc/cron.d/stop-bots-escaped";

    let with_unix = host.oneshot_under_sandbox_of(
        unit,
        "probe-boot-with-unix",
        escape,
        "| sed -e 's/^RestrictAddressFamilies=.*/& AF_UNIX/'",
    );
    assert!(
        with_unix && host.run("test -e /etc/cron.d/stop-bots-escaped").0,
        "the control could not reach systemd, so the refusal below proves nothing. journal:\n{}",
        host.journal("probe-boot-with-unix.service")
    );
    host.sh("rm /etc/cron.d/stop-bots-escaped");

    let escaped = host.oneshot_under_sandbox_of(unit, "probe-boot-escape", escape, "");
    assert!(
        !escaped && !host.run("test -e /etc/cron.d/stop-bots-escaped").0,
        "a script run by the boot unit had systemd write /etc/cron.d for it"
    );
    let wrote = host.oneshot_under_sandbox_of(
        unit,
        "probe-boot-write",
        "/usr/bin/touch /etc/cron.d/stop-bots-probe",
        "",
    );
    assert!(
        !wrote && !host.run("test -e /etc/cron.d/stop-bots-probe").0,
        "a script run by the boot unit wrote /etc/cron.d"
    );

    // And it still does its one job, the way a boot runs it.
    host.sh("nft delete table inet stop_bots");
    host.sh("systemctl restart stop-bots-firewall.service");
    assert!(
        host.run("nft get element inet stop_bots block_v4 '{ 203.0.113.90 }'")
            .0,
        "the hardened boot unit did not load the applied rules. journal:\n{}",
        host.journal(unit)
    );
}

/// The iptables boot unit is a shell script under the same sandbox, plus
/// what iptables-legacy needs. It has to bring the chain back.
#[test]
fn the_iptables_boot_unit_restores_the_chain_under_its_sandbox() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-boot-iptables");
    host.stop_bots("set-firewall-backend --backend iptables");
    host.stop_bots("add-firewall-rule --address 203.0.113.91");
    host.stop_bots("render-firewall --apply --force");
    host.sh("stop-bots install firewall");

    host.sh(
        "iptables -D INPUT -j STOP-BOTS && iptables -D FORWARD -j STOP-BOTS \
         && iptables -F STOP-BOTS && iptables -X STOP-BOTS && rm -f /run/xtables.lock",
    );
    let started = host.try_start("stop-bots-firewall.service");

    assert!(
        started,
        "the iptables boot unit failed under its sandbox. journal:\n{}",
        host.journal("stop-bots-firewall.service")
    );
    assert!(
        host.sh("iptables -S STOP-BOTS").contains("203.0.113.91"),
        "the unit ran but the chain did not come back"
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

    // The status is the whole assertion: a tarpitted client cannot produce
    // a 200 inside the same five-second window, it produces the "000"
    // above. So a 200 here *is* "the throttle is scoped to the block".
    //
    // There used to be a wall-clock bound under it as well (under 2s, then
    // under 4s). It measured the machine rather than NGINX: the time
    // includes a `podman exec` and a curl start-up, and on a loaded host
    // it failed with the client served correctly, just slowly.
    assert_eq!(
        server.status("/", "--max-time 5 -A 'Mozilla/5.0'"),
        "200",
        "the tarpit is holding everyone, not just blocked clients"
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
        client.get(&server.name, ""),
        "200",
        "the client cannot reach the server to begin with"
    );

    // The bait, fetched by the real client through the real server.
    client.get_path(&server.name, "/trap-me", "");

    let found = server.stop_bots("run-detector honeypot --access-log /var/log/nginx/access.log");
    assert!(
        found.contains(&client.address()),
        "the detector did not find the client in the log NGINX wrote:\n{found}"
    );

    server.stop_bots("render-firewall --backend nftables --out /etc/stop-bots/firewall.nft");
    server.sh("nft -f /etc/stop-bots/firewall.nft");

    assert_eq!(
        client.get(&server.name, "--max-time 5"),
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
        client.get(&server.name, ""),
        "200",
        "the client cannot reach the server to begin with"
    );

    client.get_path(&server.name, "/.env", "");
    client.get_path(&server.name, "/.git/config", "");

    let found = server.stop_bots("run-detector probe-paths --access-log /var/log/nginx/access.log");
    assert!(
        found.contains(&client.address()),
        "the detector did not find the probing client in NGINX's own log:\n{found}"
    );

    server.stop_bots("render-firewall --backend nftables --out /etc/stop-bots/firewall.nft");
    server.sh("nft -f /etc/stop-bots/firewall.nft");

    assert_eq!(
        client.get(&server.name, "--max-time 5"),
        "000",
        "the prober was detected and blocked but can still reach the server. ruleset:\n{}",
        server.sh("nft list ruleset")
    );
}

/// The other side of the detector above: not who asked for `/.env`, but
/// whether a real NGINX handed it out. `status` names the file, and stops
/// once NGINX is told to deny dotfiles the way the check's fix says.
#[test]
fn status_names_an_env_file_nginx_really_serves() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-exposed");
    server.sh("printf 'DB_PASSWORD=hunter2\\n' > /var/www/test/.env");

    let (_, out, err) = server.run("stop-bots status --db /tmp/db.sqlite3");
    let said = format!("{out}{err}");
    assert!(
        said.contains("[CRITICAL] No secrets served")
            && said.contains("http://test.example:8080/.env"),
        "status does not name the served file:\n{said}"
    );

    server.sh(
        "sed -i '/server_name/a location ~ /\\\\.(?!well-known) { deny all; }' \
         /etc/nginx/sites-enabled/test-site.conf && nginx -t && nginx -s reload && sleep 1",
    );
    let (_, out, err) = server.run("stop-bots status --db /tmp/db.sqlite3");
    let said = format!("{out}{err}");
    assert!(
        said.contains("[OK] No secrets served"),
        "the denied file is still reported:\n{said}\nsite:\n{}",
        server.sh("cat /etc/nginx/sites-enabled/test-site.conf")
    );
}

// ---- a visitor, through every detector ----

/// How many pages [`serve_linked_pages`] writes: more than the thresholds
/// of the detectors that count pages (`asset-ratio`'s 15, `refererless`'s
/// 25 distinct deep pages), so a visitor they misjudged would be convicted.
const LINKED_PAGES: usize = 30;

/// Every detector that reads the access log, as `run-detector` names them.
/// `honeypot` and `robots-violators` are left out: both need a generated
/// robots.txt, which nothing here serves.
const ACCESS_LOG_DETECTORS: &[&str] = &[
    "web-scanners",
    "spoofed-crawlers",
    "probe-paths",
    "injection",
    "protocol-probes",
    "asset-ratio",
    "rotating-ua",
    "refererless",
    "login-attempts",
    "request-rate",
];

/// A site of [`LINKED_PAGES`] pages, each linking the next and loading the
/// same stylesheet, script and image.
fn serve_linked_pages(server: &Server) {
    server.sh(&format!(
        "cd /var/www/test && printf 'body {{}}' > style.css && : > app.js && \
         printf '<svg xmlns=\"http://www.w3.org/2000/svg\"/>' > logo.svg && \
         for i in $(seq 1 {LINKED_PAGES}); do \
           printf '<link rel=stylesheet href=/style.css><script src=/app.js></script>\
<img src=/logo.svg><a href=/page-%d.html>next</a>' $((i + 1)) > page-$i.html; \
         done"
    ));
}

/// Reads the site as a person in a browser does: in at `/`, its assets
/// once (a browser caches them, which is the harder case for `asset-ratio`),
/// then every page by following its link, so each carries a `Referer`.
fn browse(client: &Client, host: &str) {
    sh_in(
        &client.name,
        &format!(
            "base=http://{host}:8080; \
             get() {{ curl -s -o /dev/null -A '{FIREFOX}' \
               -H 'Accept: text/html,*/*;q=0.8' -H 'Accept-Language: en' \"$@\"; }}; \
             get \"$base/\"; \
             for asset in style.css app.js logo.svg; do get -e \"$base/\" \"$base/$asset\"; done; \
             previous=\"$base/\"; \
             for i in $(seq 1 {LINKED_PAGES}); do \
               get -e \"$previous\" \"$base/page-$i.html\"; previous=\"$base/page-$i.html\"; \
             done"
        ),
    );
}

/// The same pages, as a crawler working from a list: no assets, no
/// `Referer`.
fn crawl(client: &Client, host: &str) {
    sh_in(
        &client.name,
        &format!(
            "for i in $(seq 1 {LINKED_PAGES}); do \
               curl -s -o /dev/null -A '{FIREFOX}' http://{host}:8080/page-$i.html; \
             done"
        ),
    );
}

const FIREFOX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";

/// The detectors that convict `address` in the server's access log, each
/// judging on its own: a dry run, because once one has stored a block the
/// next reports the address as already covered without naming it.
fn convicting_detectors(server: &Server, address: &str) -> Vec<&'static str> {
    ACCESS_LOG_DETECTORS
        .iter()
        .copied()
        .filter(|detector| {
            server
                .stop_bots(&format!(
                    "run-detector {detector} --dry-run --access-log /var/log/nginx/access.log"
                ))
                .contains(address)
        })
        .collect()
}

/// Runs every access-log detector for real, storing what each finds the
/// way `tick` does.
fn run_every_detector(server: &Server) {
    for detector in ACCESS_LOG_DETECTORS {
        server.stop_bots(&format!(
            "run-detector {detector} --access-log /var/log/nginx/access.log"
        ));
    }
}

/// **No detector takes a person for a bot.** Every one that reads the access
/// log, switched on or not, judges a browser-like visit of more pages than
/// any of their thresholds, and the firewall loaded afterwards still lets
/// the visitor in.
#[test]
fn a_visitor_reading_the_site_is_convicted_by_no_detector() {
    if !enabled() {
        return;
    }
    let net = Network::create("stop-bots-visitor-net");
    let server = Server::start_on_network("stop-bots-visitor", &net);
    let visitor = Client::start("stop-bots-visitor-client", &net);
    serve_linked_pages(&server);

    browse(&visitor, &server.name);

    let convicted = convicting_detectors(&server, &visitor.address());
    assert_eq!(
        convicted,
        Vec::<&str>::new(),
        "the visitor was convicted. access log:\n{}",
        server.sh("cat /var/log/nginx/access.log")
    );
    run_every_detector(&server);
    server.render_and_load("nftables");
    assert_eq!(
        visitor.get(&server.name, "--max-time 5"),
        "200",
        "the visitor is turned away. rules:\n{}",
        server.stop_bots("list-firewall-rules")
    );
}

/// The control for the test above: the same pages without what a browser
/// adds are convicted, by the two detectors that look for exactly that. If
/// they were not, the visitor's acquittal would only show its visit was too
/// short to judge.
#[test]
fn the_same_pages_read_without_assets_or_referer_are_convicted() {
    if !enabled() {
        return;
    }
    let net = Network::create("stop-bots-crawler-net");
    let server = Server::start_on_network("stop-bots-crawler", &net);
    let crawler = Client::start("stop-bots-crawler-client", &net);
    serve_linked_pages(&server);

    crawl(&crawler, &server.name);

    assert_eq!(
        convicting_detectors(&server, &crawler.address()),
        ["asset-ratio", "refererless"],
        "access log:\n{}",
        server.sh("cat /var/log/nginx/access.log")
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
    let host = Host::start("stop-bots-status-unenforced");

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

    // Load them, and the same command has to change its mind. The rule
    // is a set element now, and the count has to find it there rather
    // than call the ruleset behind.
    host.sh("nft -f /etc/stop-bots/firewall.nft");
    let (ok, out, err) = host.run_uncontended(&format!("stop-bots status --db {HOST_DB}"));
    let said = format!("{out}{err}");
    assert!(
        !said.contains("none loaded into the kernel") && !said.contains("behind"),
        "the report does not see what was loaded:\n{said}"
    );
    assert!(
        ok,
        "with the rules loaded, nothing should be critical:\n{said}"
    );
}

/// nftables rules live in kernel memory. A host that is protected now and
/// comes back open after a reboot is worth being told about, and the
/// answer comes from systemd rather than from anything this tool wrote.
///
/// The question is whether anything re-applies *our* script. Enabling
/// `nftables.service` used to satisfy this check, although that unit loads
/// /etc/nftables.conf and never ours — so it must not change the answer,
/// and `stop-bots install firewall` must.
#[test]
fn status_notices_that_the_ruleset_will_not_survive_a_reboot() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-status-persist");
    let not_reapplied = "nothing re-applies /etc/stop-bots/firewall.nft at boot";

    let (_, out, err) = host.run_uncontended(&format!("stop-bots status --db {HOST_DB}"));
    let said = format!("{out}{err}");
    assert!(
        said.contains(not_reapplied),
        "a host with nothing re-applying the script was not told:\n{said}"
    );

    host.sh("systemctl enable nftables.service");
    let (_, out, err) = host.run_uncontended(&format!("stop-bots status --db {HOST_DB}"));
    let said = format!("{out}{err}");
    assert!(
        said.contains(not_reapplied),
        "enabling nftables.service, which loads a different file, \
         was taken as re-applying ours:\n{said}"
    );

    host.sh("stop-bots install firewall");
    let (_, out, err) = host.run_uncontended(&format!("stop-bots status --db {HOST_DB}"));
    let said = format!("{out}{err}");
    assert!(
        said.contains("/etc/stop-bots/firewall.nft is re-applied at boot"),
        "`install firewall` did not change the answer:\n{said}"
    );
}

/// **A reboot enforces only what was applied.** The internal cron, `batch`
/// without `--apply` and a bare `render-firewall` all write a script; none
/// of them may change what `stop-bots-firewall.service` loads, or a block
/// nobody applied goes live at the next boot. Checked against the real
/// unit under real systemd: apply one rule, render a second without
/// applying, then drop the table and restart the unit the way a boot
/// would.
#[test]
fn the_boot_unit_loads_only_what_was_applied() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-boot-applied");
    let root = "--root /etc/nginx/sites-enabled";

    host.stop_bots("add-firewall-rule --address 203.0.113.70");
    // `--force`: a container has no SSH log for the lockout check.
    host.stop_bots("render-firewall --apply --force");
    host.sh("stop-bots install firewall");

    host.stop_bots("add-firewall-rule --address 203.0.113.71");
    host.stop_bots("render-firewall");
    host.stop_bots(&format!("batch --no-fetch --force {root}"));
    let rendered = host.sh("cat /etc/stop-bots/firewall.next.nft");
    assert!(
        rendered.contains("203.0.113.71"),
        "the unapplied rule should be in the rendered script:\n{rendered}"
    );

    host.sh("nft delete table inet stop_bots");
    host.sh("systemctl restart stop-bots-firewall.service");

    assert!(
        host.run("nft get element inet stop_bots block_v4 '{ 203.0.113.70 }'")
            .0,
        "the applied rule did not come back with the unit"
    );
    assert!(
        !host
            .run("nft get element inet stop_bots block_v4 '{ 203.0.113.71 }'")
            .0,
        "a rule nobody applied was loaded by the boot unit"
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

// ---- the firewall backends, against the real thing ----

/// `batch` is what a real crontab runs, and it used to carry a `nftables`
/// default that no host setting could override — so an operator who chose
/// iptables got an nftables script from every cron run, at
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

    host.stop_bots("add-firewall-rule --address 203.0.113.50");
    host.stop_bots("set-firewall-backend --backend iptables");
    host.sh("rm -f /etc/stop-bots/firewall.next.sh /etc/stop-bots/firewall.next.nft");

    // No --backend: the stored choice has to decide both syntax and path.
    host.stop_bots("batch --no-fetch --force --root /etc/nginx/sites-enabled");
    assert!(
        !host.run("test -e /etc/stop-bots/firewall.next.nft").0,
        "a crontab-shaped run wrote an nftables script to a host set to iptables"
    );
    let written = host.sh("cat /etc/stop-bots/firewall.next.sh");
    assert!(
        written.starts_with("#!/bin/sh") && written.contains("203.0.113.50"),
        "the stored backend did not decide what batch generated:\n{written}"
    );

    // An explicit flag still overrides it, in both syntax and path.
    host.stop_bots("batch --no-fetch --force --backend nftables --root /etc/nginx/sites-enabled");
    let forced = host.sh("cat /etc/stop-bots/firewall.next.nft");
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
        client.get(&server.name, ""),
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
        client.get(&server.name, "--max-time 5"),
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

/// The bug from a real host: its NGINX container could no longer reach a
/// service on the host. A container's source is a private bridge address
/// arriving on the *input* hook, and the allow-list catch-all (like a feed
/// listing private space as bogons) dropped it before ufw saw a packet.
/// Private sources now get past everything derived — and an operator's own
/// block of a private range still applies, because it comes first.
#[test]
fn a_container_on_a_private_bridge_still_reaches_the_host_in_allowlist_mode() {
    if !enabled() {
        return;
    }
    let net = Network::create_private("stop-bots-private-net");
    let server = Server::start_on_network("stop-bots-private-host", &net);
    let client = Client::start("stop-bots-private-client", &net);
    let client_ip = client.address();

    server.sh("printf '192.0.2.0/24\n' > /tmp/zone.zone");
    server.stop_bots("update-country-ranges --country nl --source /tmp/zone.zone");
    server.stop_bots("add-country --country nl");
    server.stop_bots("set-geo-mode --mode allowlist");
    server.stop_bots("render-firewall --backend nftables --out /tmp/fw.nft --force");
    server.sh("nft -f /tmp/fw.nft");

    assert_eq!(
        client.get(&server.name, "--max-time 5"),
        "200",
        "the allow-list catch-all dropped {client_ip}, a private source. ruleset:\n{}",
        server.sh("nft list ruleset")
    );

    server.stop_bots(&format!(
        "add-firewall-rule --address {client_ip} --action block"
    ));
    server.stop_bots("render-firewall --backend nftables --out /tmp/fw.nft --force");
    server.sh("nft -f /tmp/fw.nft");
    assert_eq!(
        client.get(&server.name, "--max-time 5"),
        "000",
        "an explicit block of {client_ip} must still apply"
    );
}

/// `nftables`' `inet` family covers IPv4 and IPv6 in one table, and an
/// IPv6 block has to stop IPv6 packets from a real second host.
///
/// **This test used to pass without testing anything.** It added
/// 2001:db8::1 to the server's own `lo` and requested it from inside the
/// server, which failed with "connection refused" before any rule was
/// consulted: the site listens on `0.0.0.0:8080` only, so nothing answered
/// on IPv6 at all — and had anything answered, the ruleset accepts `iif
/// lo` before its sets. Reproduced by running the old request with no
/// ruleset loaded: `000`, curl exit 7. Now the request comes from a client
/// container over a dual-stack network, the site listens on IPv6 too, and
/// the same request is shown to succeed before the rule goes in.
#[test]
fn an_ipv6_rule_really_drops_ipv6_traffic() {
    if !enabled() {
        return;
    }
    let net = Network::create_dual_stack("stop-bots-ipv6-net");
    let server = Server::start_on_network("stop-bots-ipv6", &net);
    let client = Client::start("stop-bots-ipv6-client", &net);
    server.sh(
        "sed -i 's/listen 8080;/listen 8080;\\n    listen [::]:8080;/' \
         /etc/nginx/sites-enabled/test-site.conf && nginx -s reload",
    );
    let server_v6 = format!("[{}]", address_of(&server.name, "GlobalIPv6Address"));
    let client_v6 = client.address_v6();
    assert!(
        client_v6.contains(':'),
        "the client has no IPv6 address: {client_v6:?}"
    );

    // The control: without it, a request that fails for any other reason
    // reads as the rule working.
    let served = (0..20).any(|_| {
        let ok = client.get(&server_v6, "-g --max-time 2") == "200";
        if !ok {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        ok
    });
    assert!(served, "the IPv6 client was not served before any rule");

    server.stop_bots(&format!("add-firewall-rule --address {client_v6}"));
    server.stop_bots("render-firewall --backend nftables --out /tmp/fw.nft --force");
    server.sh("nft -f /tmp/fw.nft");

    assert!(
        server.in_set("block_v6", &client_v6),
        "the IPv6 rule is not in the live ruleset:\n{}",
        server.sh("nft list table inet stop_bots")
    );
    assert_eq!(
        client.get(&server_v6, "-g --max-time 5"),
        "000",
        "packets from {client_v6} were still served"
    );
    assert_eq!(
        client.get(&address_of(&server.name, "IPAddress"), "--max-time 5"),
        "200",
        "the same client over IPv4 is not blocked, so it must still be served"
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
    // And trust, which adds a `geo`, two `map`s and a second zone in
    // `conf.d`, and a clear to every block.
    server.stop_bots("add-trusted --address 2001:db8::/48");
    server.stop_bots("add-trusted --user-agent Pingdom.com_bot");
    // And an agent exemption, which sets and reads a variable of its own.
    server.stop_bots(
        "add-exempt-path --site test.example --path /remote.php/dav/ --user-agent okhttp/4.10",
    );

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

/// An agent exemption lets its client through on its paths and nowhere
/// else: not on another path, not by walking out of the prefix with `..`,
/// and not for another bot on the same path. A client let through reaches
/// the site's own `try_files`, so a missing file is its 404, where a
/// refused one gets the block's 403.
#[test]
fn an_agent_exemption_serves_only_its_client_on_only_its_paths() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-agent-exempt");
    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    server.seed_bot("okhttp", "okhttp");
    server.seed_bot("badbot", "BadBot");
    server.stop_bots("add-exempt-path --site test.example --path /dav/ --user-agent okhttp");
    server.apply_and_reload();

    for (path, user_agent, expected, why) in [
        (
            "/dav/file",
            "okhttp/4.10.0",
            "404",
            "the exempt client on its path",
        ),
        (
            "/DAV/file",
            "okhttp/4.10.0",
            "404",
            "the path, matched without case",
        ),
        (
            "/",
            "okhttp/4.10.0",
            "403",
            "the exempt client off its path",
        ),
        (
            "/dav/../index.html",
            "okhttp/4.10.0",
            "403",
            "walking out with ..",
        ),
        (
            "/dav/%2e%2e/index.html",
            "okhttp/4.10.0",
            "403",
            "walking out with %2e%2e",
        ),
        (
            "/dav/file",
            "BadBot/1.0",
            "403",
            "another bot on the exempt path",
        ),
        ("/", "Mozilla/5.0", "200", "an ordinary visitor"),
    ] {
        assert_eq!(
            server.status(path, &format!("--path-as-is -A '{user_agent}'")),
            expected,
            "{why}: {user_agent} on {path}"
        );
    }
}

// ---- trust: what NGINX and the kernel actually let through ----

/// A trusted user agent gets past a bot pattern that matches it and a
/// request-shape rule it trips, while the bot it resembles is still
/// refused. Checked against a live NGINX because every piece of the
/// mechanism — the `map` in `conf.d`, the variable it defines, the clear
/// in the sentinel block — only means anything once NGINX has parsed it.
#[test]
fn a_trusted_user_agent_is_served_past_every_block_it_trips() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-trust-ua");
    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    server.seed_bot("badbot", "BadBot");
    server.stop_bots("set-site-rule --site test.example --rule no-accept-language --enabled true");
    server.stop_bots("add-trusted --user-agent badbot-monitor");
    server.apply_and_reload();

    assert_eq!(
        server.status("/", "-A 'BadBot/1.0' -H 'Accept-Language: en'"),
        "403",
        "trusting one agent must not let the bot it resembles through"
    );
    assert_eq!(
        server.status("/", "-A 'Mozilla/5.0 (compatible; BadBot-Monitor/2.0)'"),
        "200",
        "a trusted agent (matched without case, sending no Accept-Language) was refused"
    );
}

/// A trusted range is served whatever its user agent, and never rate
/// limited — the zone is keyed on a variable that is empty for it.
#[test]
fn a_trusted_address_is_served_past_blocks_and_never_rate_limited() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-trust-addr");
    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    server.seed_bot("badbot", "BadBot");
    server.stop_bots("set-rate-limit --enabled true --rps 1 --burst 2");
    let burst = "for i in $(seq 1 12); do curl -s -o /dev/null -w '%{http_code} ' \
                 http://127.0.0.1:8080/; sleep 0.05; done";

    // Rate limiting live *before* anything is trusted, then trust added,
    // then taken away, reloading each time. That order is the one that
    // broke: `nginx -t` passed every time, and NGINX rejected the reload
    // for re-keying a zone it already had, leaving the old config serving
    // with nothing but a line in the error log to say so.
    server.apply_and_reload();
    assert_eq!(server.status("/", "-A 'BadBot/1.0'"), "403");

    // A range rather than the one address, so the `geo` lookup is doing
    // CIDR matching rather than an exact comparison.
    server.stop_bots("add-trusted --address 127.0.0.0/8");
    server.apply_and_reload();
    assert_eq!(
        server.status("/", "-A 'BadBot/1.0'"),
        "200",
        "a client from a trusted range was refused over its user agent"
    );
    let codes = server.sh(burst);
    assert!(
        !codes.contains("429"),
        "a trusted client was rate limited: {codes}"
    );

    server.stop_bots("remove-trusted --address 127.0.0.0/8");
    server.apply_and_reload();
    assert_eq!(server.status("/", "-A 'BadBot/1.0'"), "403");
    let codes = server.sh(burst);
    assert!(
        codes.contains("429"),
        "untrusted again, the burst should be limited: {codes}"
    );

    let (_, log, _) = server.run("cat /var/log/nginx/error.log");
    assert!(
        !log.contains("[emerg]"),
        "NGINX rejected a reload that `nginx -t` passed:\n{log}"
    );
}

/// The firewall half, with real packets: a client inside a blocked /24
/// still reaches the server once its own address is trusted, because the
/// accept is evaluated first.
#[test]
fn a_trusted_client_inside_a_blocked_range_still_reaches_the_server() {
    if !enabled() {
        return;
    }
    let net = Network::create("stop-bots-trust-net");
    let server = Server::start_on_network("stop-bots-trust-target", &net);
    let client = Client::start("stop-bots-trust-client", &net);
    let client_ip = client.address();
    let range = format!("{}.0/24", client_ip.rsplit_once('.').unwrap().0);

    server.stop_bots(&format!(
        "add-firewall-rule --address {range} --action block"
    ));
    server.stop_bots(&format!("add-trusted --address {client_ip}"));
    server.stop_bots("render-firewall --backend nftables --out /tmp/fw.nft --force");
    server.sh("nft -f /tmp/fw.nft");

    assert_eq!(
        client.get(&server.name, "--max-time 5"),
        "200",
        "{client_ip} is trusted but was dropped by the block on {range}"
    );

    server.stop_bots(&format!("remove-trusted --address {client_ip}"));
    server.stop_bots("render-firewall --backend nftables --out /tmp/fw.nft --force");
    server.sh("nft -f /tmp/fw.nft");
    assert_eq!(
        client.get(&server.name, "--max-time 5"),
        "000",
        "without the trust, the block on {range} should drop {client_ip}"
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
    server.stop_bots("add-exempt-path --site test.example --path /blog");
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

/// A WordPress-style front controller: `try_files` sends every path that
/// is not a file on to one page, an internal redirect on which NGINX runs
/// the `server`'s `if`s again with the new `$uri`. The exemption decided
/// on the path the client asked for must stand, and must not stretch to
/// a path that only starts with it before `..` is resolved.
#[test]
fn an_exempt_path_stays_exempt_through_a_front_controller() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-frontctl");
    server.sh(
        "mkdir -p /var/www/wp && echo front > /var/www/wp/index.html && \
         printf 'server {\n    listen 8081;\n    server_name wp.example;\n    \
         root /var/www/wp;\n    location / { try_files $uri $uri/ /index.html; }\n}\n' \
         > /etc/nginx/sites-enabled/wp.conf && nginx -s reload",
    );
    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    server.seed_bot("badbot", "BadBot");
    server.stop_bots("add-exempt-path --site wp.example --path /wp-json/");
    server.apply_and_reload();

    let bot = "-A 'BadBot/1.0'";
    assert_eq!(
        server.status_on(8081, "/wp-json/wp/v2/posts", bot),
        "200",
        "the redirect to /index.html undid the exemption"
    );
    for (path, why) in [
        ("/about/", "a path that is not exempt"),
        (
            "/wp-json/../about/",
            "a path that resolves out of the exempt one",
        ),
    ] {
        assert_eq!(
            server.status_on(8081, path, &format!("--path-as-is {bot}")),
            "403",
            "{why} let the bot through: {path}"
        );
    }
}

/// `s` in single quotes for `sh -c`, so none of it is shell syntax.
fn sh_quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// User agents a site that logs in JSON (`escape=json`) can put in front of
/// an operator, each with a character NGINX's config reader or PCRE treats
/// specially, and for some a near miss: a user agent the rule would also
/// have caught had NGINX read the regex differently from how it was
/// checked. The same list as `HOSTILE_USER_AGENTS` in `src/nginx.rs`.
const HOSTILE_USER_AGENTS: [(&str, Option<&str>); 11] = [
    // Read as `...a\\|`: "a backslash, or nothing" — every visitor.
    (r"Scraper/2.1 a\|", Some("Scraper/2.1 a|")),
    // Read as `x\\*`: an x and any number of backslashes.
    (r"Scraper/2.1 x\*", Some("Scraper/2.1 x")),
    // Read as an unclosed group: `nginx -t` failed, and every apply after.
    (r"Scraper/2.1 Evil\(", None),
    (r#"Scraper/2.1 say "hi""#, None),
    (r#"Scraper/2.1 \"quoted\""#, Some(r#"Scraper/2.1 "quoted""#)),
    (r"Scraper/2.1 trailing\", None),
    // Read as a tab and a line feed.
    (r"Scraper/2.1 tab\t", Some("Scraper/2.1 tab")),
    (r"Scraper/2.1 line\n", Some("Scraper/2.1 line")),
    ("Scraper/2.1 $foo", None),
    ("Scraper/2.1 }", None),
    ("Scraper/2.1 ;", None),
];

/// The finding, end to end: blocked user agents with a backslash, a quote
/// or a brace in them, stored the way a release that took them wrote them,
/// each turn away exactly that client under a real NGINX — and not a
/// browser, not curl, not Googlebot.
///
/// Stored with `sqlite3` rather than through the CLI, because the CLI
/// now refuses a backslash in a blocked user agent: these are the
/// rows a host that upgrades already has. Two more such rows ride along:
/// path exemptions `/x\|` (which exempted every path) and `/x\(` (which
/// failed `nginx -t`), and a bot list with patterns PCRE refuses, which
/// failed `nginx -t` at apply time and rolled every apply back.
#[test]
fn hostile_stored_entries_block_exactly_their_client_under_a_real_nginx() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-hostile");
    let db = "/tmp/db.sqlite3";
    let stop_bots = |args: &str| host.sh(&format!("stop-bots {args} --db {db}"));
    stop_bots("scan-sites --root /etc/nginx/sites-enabled");

    let mut sql = String::new();
    for (user_agent, _) in HOSTILE_USER_AGENTS {
        sql.push_str(&format!(
            "INSERT INTO blocked_user_agents (user_agent, blocked_at) VALUES ('{}', 0);\n",
            user_agent.replace('\'', "''")
        ));
    }
    for path in [r"/x\|", r"/x\("] {
        sql.push_str(&format!(
            "INSERT INTO site_path_exemptions (site_id, path) \
             SELECT id, '{path}' FROM sites WHERE server_name = 'test.example';\n"
        ));
    }
    host.sh(&format!("sqlite3 {db} <<'SQL'\n{sql}SQL"));

    let json = r#"[{"id":"listed","categories":["ai"],"pattern":{"accepted":["ListedBot","Bot[z-a]x","Botx{2,1}","Botx{99999}"],"forbidden":[]}}]"#;
    host.sh(&format!("cat > /tmp/bots.json <<'JSON'\n{json}\nJSON"));
    let fetched = stop_bots("update-bot-lists --source /tmp/bots.json");
    assert!(
        fetched.contains("left out 3 pattern(s)"),
        "the fetch did not say what it left out:\n{fetched}"
    );

    let (applied, warned) = {
        let (ok, stdout, stderr) = host.run(&format!(
            "stop-bots apply-blocks --root /etc/nginx/sites-enabled --no-reload --db {db}"
        ));
        assert!(ok, "apply-blocks failed:\n{stdout}{stderr}");
        (stdout, stderr)
    };
    assert!(
        warned.contains(r#"exempt path "/x\\|""#) && warned.contains(r#"exempt path "/x\\(""#),
        "the unwritten exemptions were not named:\n{applied}{warned}"
    );
    let (ok, stdout, stderr) = host.run("nginx -t");
    assert!(
        ok,
        "nginx rejected the generated config:\n{stdout}{stderr}\n{}",
        host.sh("cat /etc/nginx/sites-enabled/test-site.conf")
    );
    host.sh("systemctl reload nginx");
    std::thread::sleep(std::time::Duration::from_millis(300));

    let status = |user_agent: &str| {
        host.run(&format!(
            "curl -s -o /dev/null -w '%{{http_code}}' -A {} http://127.0.0.1:8080/",
            sh_quoted(user_agent)
        ))
        .1
        .trim()
        .to_string()
    };
    for (user_agent, near_miss) in HOSTILE_USER_AGENTS {
        assert_eq!(status(user_agent), "403", "{user_agent:?} was served");
        if let Some(near_miss) = near_miss {
            assert_eq!(
                status(near_miss),
                "200",
                "{near_miss:?} was refused by the rule for {user_agent:?}"
            );
        }
    }
    assert_eq!(
        status("ListedBot/1.0"),
        "403",
        "the list's good pattern was lost"
    );
    for ordinary in [
        "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
        "curl/8.14.1",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    ] {
        assert_eq!(status(ordinary), "200", "{ordinary:?} was refused");
    }
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
    for (set, element) in [
        ("block_v4", "203.0.113.9"),
        ("block_v4", "198.51.100.0/24"),
        ("block_v6", "2001:db8:1:2::/64"),
        ("allow_v4", "192.0.2.7"),
    ] {
        assert!(
            server.in_set(set, element),
            "{element} missing from {set} in the loaded ruleset:\n{ruleset}"
        );
    }
    for rule in [
        "ip saddr @block_v4 drop",
        "ip6 saddr @block_v6 drop",
        "ip saddr @allow_v4 accept",
    ] {
        assert!(
            ruleset.contains(rule),
            "{rule:?} missing from the loaded ruleset:\n{ruleset}"
        );
    }

    // The script resets only its own table, so applying twice is a no-op
    // rather than a duplicate — the idiom TODO.md flagged as reasoned-
    // through but unverified.
    server.sh("nft -f /tmp/fw.nft");
    let twice = server.sh("nft list table inet stop_bots");
    assert_eq!(
        twice.matches("203.0.113.9").count(),
        1,
        "re-applying must not duplicate elements:\n{twice}"
    );
    assert_eq!(
        twice.matches("@block_v4").count(),
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

// ---- the port-scan detector, against a real firewall ----

impl Client {
    /// Opens a TCP connection to `port` on `host` and says how it went:
    /// curl's exit code, 7 for a refusal (a closed port answering) and 28
    /// for a timeout (a port whose packets are dropped).
    fn connect(&self, host: &str, port: u16) -> String {
        let (_, stdout, _) = exec_in(
            &self.name,
            &format!("curl -s --max-time 3 telnet://{host}:{port} </dev/null; echo $?"),
        );
        stdout.trim().to_string()
    }
}

/// The joins between the halves, for one backend: the trap loads into a
/// real firewall, drops a real client's connection to a trap port while
/// other closed ports still refuse, and the client that a kernel log names
/// for two trap ports is then blocked from the web server.
///
/// The kernel log line is written by hand, in the kernel's format, with
/// the real client's address: a container's network namespace does not
/// log to the kernel log (`nf_log_all_netns` is off), and a container
/// could not read it if it did. The parser's side of that format is
/// tested in `portscan`; this is the rest.
fn port_scan_end_to_end(backend: &str) {
    let net = Network::create(&format!("stop-bots-portscan-{backend}-net"));
    let server = Server::start_on_network(&format!("stop-bots-portscan-{backend}"), &net);
    let client = Client::start(&format!("stop-bots-portscan-{backend}-client"), &net);
    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    let address = client.address();

    server.stop_bots("set-detector port-scanners --enabled true");
    server.render_and_load(backend);

    let script = server.sh("cat /tmp/fw");
    assert!(
        script.contains("stop-bots-trap: "),
        "no trap in the script:\n{script}"
    );
    assert_eq!(
        client.connect(&server.name, 23),
        "28",
        "a trap port was not dropped. script:\n{script}"
    );
    assert_eq!(
        client.connect(&server.name, 8081),
        "7",
        "a closed port that is no trap port no longer refuses. script:\n{script}"
    );
    assert_eq!(
        client.get(&server.name, "--max-time 5"),
        "200",
        "the trap stopped the web server. script:\n{script}"
    );

    let line = |port: u16| {
        format!(
            "Oct 16 10:00:00 server kernel: [100.000000] stop-bots-trap: IN=eth0 OUT= \
             SRC={address} DST=198.51.100.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF \
             PROTO=TCP SPT=40000 DPT={port} WINDOW=64240 RES=0x00 SYN URGP=0"
        )
    };
    server.sh(&format!(
        "printf '%s\\n%s\\n' '{}' '{}' > /tmp/kern.log",
        line(23),
        line(445)
    ));
    let found = server.stop_bots("run-detector port-scanners --kernel-log /tmp/kern.log");
    assert!(
        found.contains(&address),
        "the detector did not find {address}:\n{found}"
    );
    server.render_and_load(backend);

    assert_eq!(
        client.get(&server.name, "--max-time 5"),
        "000",
        "the port scanner was blocked but still reaches the web server"
    );
}

#[test]
fn a_port_scanner_is_trapped_then_blocked_under_nftables() {
    if !enabled() {
        return;
    }
    port_scan_end_to_end("nftables");
}

#[test]
fn a_port_scanner_is_trapped_then_blocked_under_iptables() {
    if !enabled() {
        return;
    }
    port_scan_end_to_end("iptables");
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
        server.in_set("block_v4", "203.0.113.9") && ruleset.contains("ip saddr @block_v4 drop"),
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

    // Beside `--out`, which names the applied script: nothing was applied.
    assert!(
        server.run("test -s /tmp/fw.next.nft").0,
        "the script should have been written"
    );
    assert!(
        !server.run("test -e /tmp/fw.nft").0,
        "and not where the applied script goes"
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

// ---- sets, restores and upgrades: the firewall at scale ----

/// The /28 a test network put `ip` in: the range to block around a
/// client, so that an Allow for the client alone has something to beat.
fn subnet_28(ip: &str) -> String {
    let (head, last) = ip.rsplit_once('.').expect("an IPv4 address");
    let last: u8 = last.parse().expect("an IPv4 address");
    format!("{head}.{}/28", last / 16 * 16)
}

/// Real packets against both halves of the ordering the sets must keep:
/// an address inside a blocked range is dropped, and an Allow given
/// before that range still lets its one client through.
fn allow_ahead_of_a_blocked_range_wins(backend: &str, prefix: &str) {
    let net = Network::create(&format!("{prefix}-net"));
    let server = Server::start_on_network(&format!("{prefix}-server"), &net);
    let client = Client::start(&format!("{prefix}-client"), &net);
    let client_ip = client.address();
    let range = subnet_28(&client_ip);

    server.stop_bots(&format!(
        "add-firewall-rule --address {client_ip} --action allow"
    ));
    server.stop_bots(&format!(
        "add-firewall-rule --address {range} --action block"
    ));
    server.render_and_load(backend);
    assert_eq!(
        client.get(&server.name, "--max-time 5"),
        "200",
        "{backend}: the Allow for {client_ip} came first and must beat the block of {range}. \
         script:\n{}",
        server.sh("cat /tmp/fw")
    );

    // The Allow was rule 1. Without it the range decides.
    server.stop_bots("remove-firewall-rule --id 1");
    server.render_and_load(backend);
    assert_eq!(
        client.get(&server.name, "--max-time 5"),
        "000",
        "{backend}: {client_ip} is inside the blocked {range} and must be dropped. script:\n{}",
        server.sh("cat /tmp/fw")
    );
}

#[test]
fn nftables_sets_drop_a_listed_address_and_an_allow_ahead_still_wins() {
    if !enabled() {
        return;
    }
    allow_ahead_of_a_blocked_range_wins("nftables", "stop-bots-sets");
}

#[test]
fn an_iptables_restore_drops_a_listed_address_and_an_allow_ahead_still_wins() {
    if !enabled() {
        return;
    }
    allow_ahead_of_a_blocked_range_wins("iptables", "stop-bots-restore");
}

/// A detector's block expires, and since sets the kernel is what lets it
/// go: the element carries a `timeout`, and nothing has to apply the
/// script again for the block to lift.
#[test]
fn a_timed_block_is_loaded_with_a_timeout_that_the_kernel_honours() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-timeout");
    server.sh(
        "for i in $(seq 25); do echo 'Aug 17 10:00:01 host sshd[100]: Failed password \
         for root from 203.0.113.50 port 4444 ssh2'; done > /tmp/auth.log",
    );
    server.stop_bots("run-detector ssh-scanners --ssh-log /tmp/auth.log --ttl-days 1");
    server.render_and_load("nftables");

    let set = server.sh("nft list set inet stop_bots block_v4");
    assert!(
        set.contains("203.0.113.50 timeout") && set.contains("expires"),
        "the detector's block should be a timed element:\n{set}"
    );

    // A day is too long to wait for, so the same script with the timeout
    // cut to a few seconds: the kernel, not a re-render, has to remove it.
    // Loaded and looked up in one exec, so a slow runner cannot spend the
    // timeout between the two.
    server.sh("sed -E 's/timeout [0-9dhms]+/timeout 4s/' /tmp/fw > /tmp/fw-short");
    let (present, _, stderr) = server
        .run("nft -f /tmp/fw-short && nft get element inet stop_bots block_v4 '{ 203.0.113.50 }'");
    assert!(
        present,
        "the element should be there before its timeout: {stderr}"
    );
    server.sh("sleep 5");
    assert!(
        !server.in_set("block_v4", "203.0.113.50"),
        "the kernel should have dropped the element when its timeout ran out:\n{}",
        server.sh("nft list set inet stop_bots block_v4")
    );
}

/// IPv6 used to be skipped by this backend altogether, including every
/// /64 a detector writes. It goes to ip6tables now, into the same chain
/// shape with the same jump.
#[test]
fn the_iptables_backend_loads_ipv6_rules_into_ip6tables() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-ip6tables");
    server.stop_bots("add-firewall-rule --address 2001:db8:1:2::/64 --action block");
    server.stop_bots("add-firewall-rule --address 203.0.113.9 --action block");
    server.render_and_load("iptables");

    let v6 = server.sh("ip6tables -S STOP-BOTS");
    assert!(
        v6.contains("-s 2001:db8:1:2::/64 -j DROP"),
        "the IPv6 rule is not in ip6tables:\n{v6}"
    );
    assert!(
        !v6.contains("203.0.113.9"),
        "an IPv4 rule reached ip6tables:\n{v6}"
    );
    let jumps = server.sh("ip6tables -S INPUT");
    assert!(
        jumps.contains("-A INPUT -j STOP-BOTS"),
        "nothing jumps to the IPv6 chain:\n{jumps}"
    );
    assert!(
        server.sh("iptables -S STOP-BOTS").contains("203.0.113.9"),
        "the IPv4 half is missing"
    );
}

/// **An interactive apply nobody keeps is undone by systemd**, after the
/// session that made it is gone. The rules are applied from a terminal,
/// which arms a `systemd-run` timer before they load; the CLI is then
/// killed mid-countdown, as a dropped SSH session would kill it. The
/// timer, which belongs to PID 1 and not to the session, loads the
/// previous script again, and the boot script is never replaced.
#[test]
fn an_apply_nobody_keeps_is_reverted_by_systemd_after_the_session_dies() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-revert");
    let applied = "/etc/stop-bots/firewall.nft";
    let loaded = || host.sh("nft list table inet stop_bots 2>/dev/null || true");

    // The rules to go back to, applied with no terminal: nothing armed.
    host.stop_bots("add-firewall-rule --address 203.0.113.1 --action block");
    host.stop_bots("render-firewall --apply --force");
    let kept = host.sh(&format!("cat {applied}"));
    assert!(
        loaded().contains("203.0.113.1"),
        "the first apply did not load"
    );

    // The new rules, from a terminal (`script` gives the CLI one), with
    // input that never answers.
    host.stop_bots("add-firewall-rule --address 203.0.113.2 --action block");
    host.sh(&format!(
        "(sleep 600 | setsid script -qfc 'stop-bots render-firewall --apply --force \
         --confirm-timeout 5 --db {HOST_DB}' /tmp/apply.log >/dev/null 2>&1 &)"
    ));
    let mut new_rules = String::new();
    for _ in 0..100 {
        new_rules = loaded();
        if new_rules.contains("203.0.113.2") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        new_rules.contains("203.0.113.2"),
        "the interactive apply never loaded:\n{}",
        host.sh("cat /tmp/apply.log || true")
    );
    let timers = host.sh("systemctl list-timers --all --no-legend 'stop-bots-revert-*' || true");
    assert!(
        timers.contains("stop-bots-revert-"),
        "no revert timer is armed under systemd:\n{timers}"
    );

    // The session dies without answering.
    host.sh("pkill -9 -x stop-bots; pkill -9 -x script; true");
    // Dead before its own countdown ends, so whatever reverts is the timer.
    assert_eq!(
        host.sh("pgrep -x stop-bots || true").trim(),
        "",
        "the CLI outlived the kill, so the test cannot tell its revert from the timer's"
    );

    let mut after = String::new();
    for _ in 0..200 {
        after = loaded();
        if !after.contains("203.0.113.2") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        !after.contains("203.0.113.2") && after.contains("203.0.113.1"),
        "the timer did not put the previous rules back:\n{after}\n{}",
        host.sh("journalctl --no-pager -n 30 -u 'stop-bots-revert-*' || true")
    );
    assert_eq!(
        host.sh(&format!("cat {applied}")),
        kept,
        "the boot script was replaced by rules nobody kept"
    );
}

/// **An apply that is kept stays**, under real systemd: answering yes
/// disarms the timer, so nothing reverts once the countdown has passed,
/// and the kept rules become the boot script.
#[test]
fn an_apply_that_is_kept_outlives_its_countdown() {
    if !enabled() {
        return;
    }
    let host = Host::start("stop-bots-keep");
    let loaded = || host.sh("nft list table inet stop_bots 2>/dev/null || true");
    host.stop_bots("add-firewall-rule --address 203.0.113.1 --action block");
    host.stop_bots("render-firewall --apply --force");
    host.stop_bots("add-firewall-rule --address 203.0.113.2 --action block");

    // Answers yes a second in, then keeps the terminal open past the
    // countdown.
    host.sh(&format!(
        "(sleep 1; echo y; sleep 600) | setsid script -qfc 'stop-bots render-firewall --apply \
         --force --confirm-timeout 3 --db {HOST_DB}' /tmp/apply.log >/dev/null 2>&1 &"
    ));
    std::thread::sleep(std::time::Duration::from_secs(6));

    let after = loaded();
    assert!(
        after.contains("203.0.113.2"),
        "the kept rules were reverted:\n{after}\n{}",
        host.sh("cat /tmp/apply.log || true")
    );
    assert!(
        host.sh("cat /etc/stop-bots/firewall.nft")
            .contains("203.0.113.2"),
        "the kept rules are not the boot script"
    );
    let timers = host.sh("systemctl list-timers --all --no-legend 'stop-bots-revert-*' || true");
    assert!(
        !timers.contains("stop-bots-revert-"),
        "a revert timer is still armed after keeping:\n{timers}"
    );
}

/// The reason for the restore. The old script flushed the chain and then
/// ran one process per rule under `set -e`, so a failure part way through
/// left the chain half filled until the next apply. A restore is checked
/// in full before it is committed: a failed apply leaves the previous
/// chain exactly as it was.
#[test]
fn a_failed_iptables_apply_leaves_the_previous_chain_whole() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-restore-atomic");
    server.stop_bots("add-firewall-rule --address 203.0.113.9 --action block");
    server.stop_bots("add-firewall-rule --address 203.0.113.10 --action block");
    server.render_and_load("iptables");
    let before = server.sh("iptables -S STOP-BOTS");

    // The same script with a new rule, then one iptables-restore refuses.
    server.sh(
        "sed 's|^-A STOP-BOTS -s 203.0.113.10 -j DROP$|&\\n-A STOP-BOTS -s 198.51.100.1 -j DROP\\n-A STOP-BOTS -s not-an-address -j DROP|' \
         /tmp/fw > /tmp/fw-broken",
    );
    assert!(
        server.sh("cat /tmp/fw-broken").contains("not-an-address"),
        "the test did not manage to break the script"
    );
    let (ok, _, stderr) = server.run("sh /tmp/fw-broken");
    assert!(!ok, "the broken script should fail");
    assert!(stderr.contains("not-an-address"), "stderr was:\n{stderr}");

    assert_eq!(
        server.sh("iptables -S STOP-BOTS"),
        before,
        "a failed apply changed the live chain"
    );
}

/// A host upgrading from 0.0.15 has that version's script loaded: one rule
/// per address, no sets. Loading the new one over it has to leave the new
/// shape and nothing of the old.
#[test]
fn a_ruleset_written_by_0_0_15_is_replaced_cleanly_by_sets() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-nft-upgrade");
    let old = include_str!("fixtures/nftables/written-by-0.0.15.nft");
    server.sh(&format!("cat > /tmp/old.nft <<'NFT'\n{old}NFT"));
    server.sh("nft -f /tmp/old.nft");
    assert!(
        server
            .sh("nft list table inet stop_bots")
            .contains("ip saddr 198.51.100.0/24 drop"),
        "the 0.0.15 script did not load as it used to"
    );

    server.stop_bots("add-firewall-rule --address 203.0.113.9 --action block");
    server.render_and_load("nftables");

    let table = server.sh("nft list table inet stop_bots");
    for gone in ["198.51.100.0/24", "203.0.113.7", "2001:db8::/32"] {
        assert!(
            !table.contains(gone),
            "{gone} from the 0.0.15 script survived the upgrade:\n{table}"
        );
    }
    assert!(
        server.in_set("block_v4", "203.0.113.9"),
        "the new rule is not in its set:\n{table}"
    );
}

/// The same for iptables: 0.0.15's script made the chain and the jumps
/// with plain `iptables` commands. The restore takes the chain over, and
/// the jumps are found rather than added a second time.
#[test]
fn a_chain_written_by_0_0_15_is_taken_over_by_the_restore() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-ipt-upgrade");
    let old = include_str!("fixtures/iptables/written-by-0.0.15.sh");
    server.sh(&format!("cat > /tmp/old.sh <<'SH'\n{old}SH"));
    server.sh("sh /tmp/old.sh");
    assert!(
        server
            .sh("iptables -S STOP-BOTS")
            .contains("198.51.100.0/24"),
        "the 0.0.15 script did not load as it used to"
    );

    server.stop_bots("add-firewall-rule --address 203.0.113.9 --action block");
    server.render_and_load("iptables");

    let chain = server.sh("iptables -S STOP-BOTS");
    assert_eq!(
        chain
            .lines()
            .filter(|l| l.contains(" -s "))
            .collect::<Vec<_>>(),
        vec!["-A STOP-BOTS -s 203.0.113.9/32 -j DROP"],
        "the chain should hold the new rules and only those:\n{chain}"
    );
    for hook in ["INPUT", "FORWARD"] {
        let jumps = server.sh(&format!("iptables -S {hook}"));
        assert_eq!(
            jumps.matches("-j STOP-BOTS").count(),
            1,
            "{hook} should jump to STOP-BOTS exactly once:\n{jumps}"
        );
    }
}

// ---- the stranger test: the README's quick start, on a fresh host ----

/// The two distributions the README names, each as a fresh server with
/// a web server and nftables from its own archive and nothing of ours on
/// it. See `Dockerfile.stranger` for what "fresh" includes.
#[derive(Clone, Copy)]
enum Distro {
    Debian12,
    Ubuntu2404,
}

impl Distro {
    fn slug(self) -> &'static str {
        match self {
            Distro::Debian12 => "debian-12",
            Distro::Ubuntu2404 => "ubuntu-24.04",
        }
    }

    /// The build arguments: the base image, and what that distribution's
    /// cloud image has that the other's does not.
    fn build_args(self) -> [&'static str; 4] {
        match self {
            Distro::Debian12 => ["--build-arg", "BASE=debian:12", "--build-arg", "EXTRA="],
            Distro::Ubuntu2404 => [
                "--build-arg",
                "BASE=ubuntu:24.04",
                "--build-arg",
                "EXTRA=rsyslog",
            ],
        }
    }

    fn image(self, web: Web) -> String {
        tagged(&format!(
            "stop-bots-stranger-{}{}",
            self.slug(),
            web.suffix()
        ))
    }

    /// Builds this distribution's image with `web` once per run, the way
    /// [`build_host_image`] does the other.
    fn build(self, web: Web) {
        static BUILT: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        let image = self.image(web);
        let mut built = BUILT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !built.contains(&image) {
            with_build_lock(|| build_unless_current(&image, || self.build_now(web)));
            built.push(image);
        }
    }

    fn build_now(self, web: Web) {
        let ctx = stage_binary();
        let out = Command::new(runtime())
            .args(["build", "-q", "-f", &format!("{ctx}/Dockerfile.stranger")])
            .args(self.build_args())
            .args(["--build-arg", &format!("SERVER={}", web.package())])
            .args(["-t", &self.image(web), &ctx])
            .output()
            .expect("failed to run the image build");
        assert!(
            out.status.success(),
            "{} build ({}) failed:\n{}",
            runtime(),
            self.slug(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// The web server on a stranger's host, as its distribution packages it.
#[derive(Clone, Copy)]
enum Web {
    Nginx,
    Apache,
}

impl Web {
    /// The package, which is also the name of its unit.
    fn package(self) -> &'static str {
        match self {
            Web::Nginx => "nginx",
            Web::Apache => "apache2",
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Web::Nginx => "",
            Web::Apache => "-apache",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Web::Nginx => "NGINX",
            Web::Apache => "Apache",
        }
    }

    fn conf_dir(self) -> &'static str {
        match self {
            Web::Nginx => "/etc/nginx",
            Web::Apache => "/etc/apache2",
        }
    }

    /// The site the package enables, on port 80.
    fn default_site(self) -> &'static str {
        match self {
            Web::Nginx => "/etc/nginx/sites-available/default",
            Web::Apache => "/etc/apache2/sites-available/000-default.conf",
        }
    }

    fn config_test(self) -> &'static str {
        match self {
            Web::Nginx => "nginx -t",
            Web::Apache => "apache2ctl configtest",
        }
    }

    /// What the README's quick start asks of this server after installing
    /// and before the first look: nothing for NGINX, the default; for
    /// Apache, to say so once and to enable the module the blocks are
    /// written in.
    fn setup(self) -> &'static [&'static str] {
        match self {
            Web::Nginx => &[],
            Web::Apache => &["stop-bots set-web-server apache", "a2enmod rewrite"],
        }
    }
}

/// The `.deb` to install, from `STOP_BOTS_STRANGER_DEB`, or `None` with the
/// reason printed.
///
/// A package rather than `CARGO_BIN_EXE_stop-bots`, for two reasons. The
/// quick start installs a package, and the package is part of what a
/// stranger meets: its dependencies, its man pages, where it puts the
/// binary. And the binary this test run compiled links the build machine's
/// glibc, which is newer than Debian 12's, so it would not even start
/// there. The released package is static (musl), and only a package built
/// the same way tests what ships. `make stranger-test` builds one and runs
/// these; CI does the same in its `stranger` job.
fn stranger_deb() -> Option<String> {
    match std::env::var("STOP_BOTS_STRANGER_DEB") {
        Ok(path) if !path.is_empty() => {
            assert!(
                std::path::Path::new(&path).is_file(),
                "STOP_BOTS_STRANGER_DEB names {path}, which is not a file"
            );
            Some(path)
        }
        _ => {
            stop_bots::say_err!(
                "skipping: the stranger test installs a .deb. Set STOP_BOTS_STRANGER_DEB to one \
                 built for x86_64-unknown-linux-musl, or run `make stranger-test`."
            );
            None
        }
    }
}

/// Whether to run `batch --apply` exactly as the quick start writes it,
/// which downloads every bot list and crawler range from the internet.
///
/// Off by default, so the suite stays hermetic: a feed that is down, or a
/// runner without outbound access, would otherwise turn it red for a
/// reason that is nobody's commit. Off, `batch` gets `--no-fetch` and
/// blocks from the list compiled into the binary, which is what a host
/// without outbound access runs anyway. CI's weekly run turns it on, which
/// is where "the world changed" failures belong.
///
/// Not a URL override pointing the downloads at a local server: that would
/// be a switch in the shipped binary that redirects where its blocklists
/// come from, and it would test reqwest rather than this project (see
/// "Coverage" in CONTRIBUTING.md).
fn stranger_fetches() -> bool {
    std::env::var_os("STOP_BOTS_STRANGER_FETCH").is_some_and(|value| !value.is_empty())
}

/// A user agent from the compiled-in scanner list, which the default
/// policy blocks. From the built-in list rather than a downloaded one so
/// that the hermetic run can block it.
const SCANNER_UA: &str = "Mozilla/5.0 (compatible; ModatScanner/1.0)";
const BROWSER_UA: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0";

impl Client {
    /// The status code for `url`, `000` when nothing answered: the
    /// stranger's host serves the distribution's default site, on port 80.
    fn status_of(&self, url: &str, extra: &str) -> String {
        let (_, stdout, _) = exec_in(
            &self.name,
            &format!("curl -s -o /dev/null -w '%{{http_code}}' {extra} {url}"),
        );
        stdout.trim().to_string()
    }

    /// [`Self::status_of`], polled until it is `want` or five seconds have
    /// passed: a reload is asynchronous, and an old worker can still
    /// answer the first request after one.
    fn eventually(&self, url: &str, extra: &str, want: &str) -> String {
        let mut got = String::new();
        for _ in 0..50 {
            got = self.status_of(url, extra);
            if got == want {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        got
    }
}

impl Host {
    /// Runs one quick-start command as the README gives it, and returns
    /// what it printed. A stranger has no reason to expect any of them to
    /// fail, so a failure is the finding, with everything it said.
    fn quick_start(&self, command: &str) -> String {
        let (ok, stdout, stderr) = self.run(command);
        let said = format!("{stdout}{stderr}");
        assert!(ok, "`{command}` failed on a fresh host:\n{said}");
        said
    }

    /// What `uninstall` promises to put back, read the same way each
    /// time: every file under the web server's config by hash, the nft
    /// tables, the units, and /etc/stop-bots.
    fn footprint(&self, web: Web) -> String {
        self.sh(&format!(
            "set -e\n\
             find {} -type f | sort | xargs sha256sum\n\
             echo '-- nft'; nft list tables\n\
             echo '-- units'; find /etc/systemd/system -name 'stop-bots*' | sort\n\
             systemctl list-unit-files 'stop-bots*' --no-legend | sort\n\
             echo '-- /etc/stop-bots'; ls -A /etc/stop-bots 2>/dev/null || true",
            web.conf_dir()
        ))
    }
}

/// **A stranger, following only the README's quick start, from install to
/// blocking to uninstall, on a fresh `distro` running `web`.**
///
/// Every command is the quick start's, run as it is written, in its order:
///
/// ```text
/// apt install ./stop-bots_*.deb
/// stop-bots set-web-server apache    (Apache only)
/// a2enmod rewrite                    (Apache only)
/// stop-bots status
/// stop-bots batch --dry-run --diff
/// stop-bots batch --apply
/// stop-bots install firewall
/// stop-bots status
/// stop-bots uninstall all --dry-run
/// stop-bots uninstall all
/// ```
///
/// with one deviation, `--no-fetch` on `batch --apply` unless
/// [`stranger_fetches`], and no other setup: no seeded bot, no site of
/// ours, no `--root`, `--db`, `--ssh-log` or `--force`. Whatever the
/// defaults find on a fresh host is what the test gets. As root, as `sudo`
/// would run it; the container's shell already is.
///
/// "Blocking" is checked from a second container, from its own address:
/// the web server turns away a scanner's user agent and serves a browser, and a
/// client that asks for `/.env` is blocked by the probe-path detector on
/// the next pass and then dropped by nftables. After `install firewall`
/// the table is deleted and the unit restarted, the way a boot loads it,
/// and only what was applied comes back. After `uninstall all`, the host
/// is as it was before the package was installed.
fn a_stranger_follows_the_quick_start(distro: Distro, web: Web) {
    if !enabled() {
        return;
    }
    let Some(deb) = stranger_deb() else {
        return;
    };
    distro.build(web);
    // No dots: the client reaches the host by this name, and Apache answers
    // 400 to a `Host` whose label after a dot starts with digits, as
    // `...-24.04-apache` would, which it takes for a malformed address.
    let tag = format!("stop-bots-stranger-{}{}", distro.slug(), web.suffix()).replace('.', "-");
    let net = Network::create(&format!("{tag}-net"));
    let host = Host::boot_image(&tag, &distro.image(web), Some(&net));
    let client = Client::start(&format!("{tag}-client"), &net);
    let site = format!("http://{}/", host.name);
    let scanner = format!("-A '{SCANNER_UA}'");
    let fetch = if stranger_fetches() {
        ""
    } else {
        " --no-fetch"
    };

    host.sh(&format!("systemctl start {}.service", web.package()));
    let pristine = host.footprint(web);
    assert_eq!(
        client.eventually(&site, &scanner, "200"),
        "200",
        "a fresh {} should serve everyone",
        web.name()
    );

    // Installing it: the package, with no network, so a dependency it
    // forgets to declare fails here rather than being fetched.
    host.put(&deb, "/root/stop-bots.deb");
    host.quick_start("DEBIAN_FRONTEND=noninteractive apt-get install -y /root/stop-bots.deb");
    //
    // The documentation is checked in dpkg's own list of what it
    // installed, not on disk: Ubuntu's container and minimal cloud images
    // tell dpkg to skip /usr/share/man, for every package alike.
    assert_eq!(host.sh("command -v stop-bots").trim(), "/usr/bin/stop-bots");
    let files = host.sh("dpkg -L stop-bots");
    for path in [
        "/usr/share/man/man1/stop-bots-batch.1.gz",
        "/usr/share/bash-completion/completions/stop-bots",
    ] {
        assert!(
            files.lines().any(|line| line == path),
            "the package does not install {path}:\n{files}"
        );
    }

    // Telling it about the web server, where the README asks to.
    for step in web.setup() {
        host.quick_start(step);
    }

    // Before anything: a first look, and the plan.
    host.quick_start("stop-bots status");
    let default_site = format!("sha256sum {}", web.default_site());
    let untouched = host.sh(&default_site);
    let plan = host.quick_start("stop-bots batch --dry-run --diff");
    for (what, needle) in [
        // A fresh host has no SSH login on record, and nothing in a first
        // apply blocks every address, so the check says it found no one
        // to check rather than that it passed, and lets the apply through.
        (
            "the SSH log the lockout check reads",
            "lockout check found no one to check",
        ),
        ("the block it would add", "+    # BEGIN stop-bots"),
        ("a scanner the binary knows", "ModatScanner"),
    ] {
        assert!(
            plan.contains(needle),
            "the dry run does not show {what}:\n{plan}"
        );
    }
    assert_eq!(
        host.sh(&default_site),
        untouched,
        "the dry run changed the site"
    );

    // Blocking.
    let applied = host.quick_start(&format!("stop-bots batch --apply{fetch}"));
    assert_eq!(
        client.eventually(&site, &scanner, "403"),
        "403",
        "a scanner's user agent is still served. batch said:\n{applied}"
    );
    assert_eq!(
        client.status_of(&site, &format!("-A '{BROWSER_UA}'")),
        "200",
        "a browser is no longer served"
    );

    client.status_of(&format!("{site}.env"), "");
    let pass = host.quick_start(&format!("stop-bots batch --apply{fetch}"));
    let prober = client.address();
    let in_kernel = |address: &str| {
        host.run(&format!(
            "nft get element inet stop_bots block_v4 '{{ {address} }}'"
        ))
        .0
    };
    assert!(
        in_kernel(&prober),
        "the client that asked for /.env is not in the kernel's set. batch said:\n{pass}\n{}",
        host.ruleset()
    );
    assert_eq!(
        client.status_of(&site, "--max-time 5"),
        "000",
        "the prober is blocked and still reaches {}",
        web.name()
    );

    // Persistence: the unit loads what was applied, and nothing else.
    let installed = host.quick_start("stop-bots install firewall");
    assert!(
        installed.contains("holds the rules the last apply loaded"),
        "install firewall tells a host that has applied to go and apply:\n{installed}"
    );
    let status = host.quick_start("stop-bots status");
    for level in ["[WARN]", "[CRITICAL]"] {
        assert!(
            !status.contains(level),
            "the quick start ends with a {level}:\n{status}"
        );
    }
    let unapplied = "203.0.113.99";
    host.sh(&format!(
        "stop-bots add-firewall-rule --address {unapplied}"
    ));
    host.sh("stop-bots render-firewall");
    host.sh("nft delete table inet stop_bots");
    host.sh("systemctl restart stop-bots-firewall.service");
    assert!(
        in_kernel(&prober),
        "the applied rules did not come back with the unit:\n{}",
        host.journal("stop-bots-firewall.service")
    );
    assert!(
        !in_kernel(unapplied),
        "the unit loaded a rule that was rendered and never applied"
    );

    // And back out.
    let before = host.footprint(web);
    let dry = host.quick_start("stop-bots uninstall all --dry-run");
    assert_eq!(
        host.footprint(web),
        before,
        "the dry run changed something:\n{dry}"
    );
    let removed = host.quick_start("stop-bots uninstall all");
    // Without `--purge`, the README says, the database and the host
    // settings file stay: what the operator set is not thrown away by a
    // plain uninstall. Everything else is as it was.
    assert_eq!(
        host.footprint(web),
        format!("{pristine}host.conf\n"),
        "the host is not as it was before stop-bots, bar host.conf. uninstall said:\n{removed}"
    );
    assert!(
        !removed.contains("did not write"),
        "uninstall called a file of its own somebody else's:\n{removed}"
    );
    let purged = host.quick_start("stop-bots uninstall all --purge");
    assert_eq!(
        host.footprint(web),
        pristine,
        "--purge left something behind. It said:\n{purged}"
    );
    let (valid, out, err) = host.run(web.config_test());
    assert!(
        valid,
        "{} does not load what uninstall left:\n{out}{err}",
        web.name()
    );
    assert_eq!(
        client.eventually(&site, &scanner, "200"),
        "200",
        "the scanner, and the blocked prober, are still turned away"
    );
}

#[test]
fn a_stranger_on_debian_12_goes_from_install_to_blocking_to_uninstall() {
    a_stranger_follows_the_quick_start(Distro::Debian12, Web::Nginx);
}

#[test]
fn a_stranger_on_ubuntu_24_04_goes_from_install_to_blocking_to_uninstall() {
    a_stranger_follows_the_quick_start(Distro::Ubuntu2404, Web::Nginx);
}

#[test]
fn a_stranger_on_ubuntu_24_04_with_apache_goes_from_install_to_blocking_to_uninstall() {
    a_stranger_follows_the_quick_start(Distro::Ubuntu2404, Web::Apache);
}

// ---- Apache ----
//
// The same promise the NGINX tests above make, kept for Apache: what this
// project writes is loaded by a real `apache2ctl configtest`, and real
// requests are turned away or let through as the policy says. Driven
// through the CLI exactly as an operator would, after `set-web-server
// apache`. Nothing here needs `NET_ADMIN` or a network of its own.

/// The Apache image — see `Dockerfile.apache`.
fn apache_image() -> String {
    tagged("stop-bots-apache")
}

fn build_apache_image() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        with_build_lock(|| build_unless_current(&apache_image(), build_apache_image_now))
    });
}

fn build_apache_image_now() {
    let ctx = stage_binary();
    let out = Command::new(runtime())
        .args([
            "build",
            "-q",
            "-f",
            &format!("{ctx}/Dockerfile.apache"),
            "-t",
            &apache_image(),
            &ctx,
        ])
        .output()
        .expect("failed to run the image build");
    assert!(
        out.status.success(),
        "{} build (Apache image) failed:\n{}",
        runtime(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A running Apache with one site, `test.example` on port 8080, and
/// stop-bots told it is Apache's. Removed on drop.
struct Apache {
    name: String,
}

/// The site file as Debian keeps it: in `sites-available`, linked from
/// `sites-enabled`.
const APACHE_SITE: &str = "/etc/apache2/sites-available/test-site.conf";

impl Apache {
    fn start(name: &str) -> Apache {
        build_apache_image();
        let name = scoped(name);
        remove_container(&name);
        let out = Command::new(runtime())
            .args(["run", "-d", "--name", &name, &apache_image()])
            .output()
            .expect("failed to start the container");
        assert!(
            out.status.success(),
            "{} run failed:\n{}",
            runtime(),
            String::from_utf8_lossy(&out.stderr)
        );
        let apache = Apache { name };
        apache.sh("apache2ctl start");
        apache.wait_until_serving();
        let chosen = apache.stop_bots("set-web-server apache");
        assert!(chosen.contains("Apache"), "set-web-server said:\n{chosen}");
        // Debian's two disabled defaults are found too, in
        // `sites-available`, as NGINX's are: three in all.
        let scanned = apache.stop_bots("scan-sites");
        assert!(
            scanned.contains("Discovered 3 site(s)"),
            "scan-sites said:\n{scanned}"
        );
        apache
    }

    fn run(&self, cmd: &str) -> (bool, String, String) {
        exec_in(&self.name, cmd)
    }

    fn sh(&self, cmd: &str) -> String {
        sh_in(&self.name, cmd)
    }

    fn stop_bots(&self, args: &str) -> String {
        self.sh(&format!("stop-bots {args} --db /tmp/db.sqlite3"))
    }

    /// One blocked bot, through the real bot-list parser; see
    /// [`Server::seed_bot`].
    fn seed_bot(&self, id: &str, pattern: &str) {
        let json = format!(
            r#"[{{"id":"{id}","categories":["ai"],"pattern":{{"accepted":["{pattern}"],"forbidden":[]}},"url":"https://example.invalid/{id}"}}]"#
        );
        self.sh(&format!("cat > /tmp/bots.json <<'JSON'\n{json}\nJSON"));
        self.stop_bots("update-bot-lists --source /tmp/bots.json");
    }

    /// `apply-blocks` as an operator runs it: tested with `apache2ctl
    /// configtest` and reloaded through the `systemctl` shim, which is a
    /// graceful restart — asynchronous, so this waits for it.
    fn apply(&self) -> String {
        let said = self.stop_bots("apply-blocks");
        let (ok, stdout, stderr) = self.run("apache2ctl configtest");
        assert!(ok, "the generated config does not load:\n{stdout}{stderr}");
        std::thread::sleep(std::time::Duration::from_millis(700));
        self.wait_until_serving();
        said
    }

    fn wait_until_serving(&self) {
        for _ in 0..50 {
            if self.status("/", "") != "000" {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("Apache never answered on port 8080");
    }

    /// The status Apache answers `path` with, `000` for no answer.
    fn status(&self, path: &str, curl_args: &str) -> String {
        let (_, stdout, _) = self.run(&format!(
            "curl -s -o /dev/null -w '%{{http_code}}' {curl_args} http://127.0.0.1:8080{path}"
        ));
        stdout.trim().to_string()
    }

    fn body(&self, path: &str, curl_args: &str) -> String {
        self.sh(&format!("curl -s {curl_args} http://127.0.0.1:8080{path}"))
    }
}

impl Drop for Apache {
    fn drop(&mut self) {
        remove_container(&self.name);
    }
}

const BAD_AGENT: &str = "-A 'Mozilla/5.0 (compatible; EvilBot/1.0)'";
const BROWSER: &str = "-A 'Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0'";

#[test]
fn apache_turns_away_a_blocked_bot_and_serves_everyone_else() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-blocks");
    apache.seed_bot("evilbot", "EvilBot");
    apache.apply();

    assert_eq!(apache.status("/", BAD_AGENT), "403");
    // Case-insensitive, as NGINX's `~*` is.
    assert_eq!(apache.status("/", "-A 'evilbot'"), "403");
    assert_eq!(apache.status("/", BROWSER), "200");
    // Written where the site is, which the enabled link still reaches.
    let site = apache.sh(&format!("cat {APACHE_SITE}"));
    assert!(site.contains("# BEGIN stop-bots"), "site file:\n{site}");
    assert!(
        apache
            .sh("readlink -f /etc/apache2/sites-enabled/test-site.conf")
            .trim()
            == APACHE_SITE,
        "the enabled link no longer leads to the site file"
    );
}

#[test]
fn apache_sends_the_response_each_setting_asks_for() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-responses");
    apache.seed_bot("evilbot", "EvilBot");
    // `close` and `tarpit` are NGINX's, and mod_rewrite will not send a
    // 418; on Apache each is a 403.
    for (response, code) in [
        ("not-found", "404"),
        ("gone", "410"),
        ("too-many-requests", "429"),
        ("teapot", "403"),
        ("close", "403"),
        ("tarpit", "403"),
        ("forbidden", "403"),
    ] {
        apache.stop_bots(&format!("set-block-response --response {response}"));
        apache.apply();
        assert_eq!(
            apache.status("/", BAD_AGENT),
            code,
            "a blocked request under `{response}`"
        );
        assert_eq!(
            apache.status("/", BROWSER),
            "200",
            "a browser under `{response}`"
        );
    }
}

#[test]
fn apache_serves_robots_txt_even_to_a_bot_it_blocks() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-robots");
    apache.seed_bot("evilbot", "EvilBot");
    apache.stop_bots("set-robots-txt --enabled true");
    apache.apply();

    assert_eq!(apache.status("/robots.txt", BAD_AGENT), "200");
    let robots = apache.body("/robots.txt", BAD_AGENT);
    assert!(
        robots.contains("User-agent: EvilBot"),
        "robots.txt:\n{robots}"
    );
    assert!(robots.contains("Disallow: /"), "robots.txt:\n{robots}");
    // Only that file: the rest of the site still turns the bot away.
    assert_eq!(apache.status("/", BAD_AGENT), "403");
}

#[test]
fn apache_lets_exempt_paths_and_trusted_clients_through() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-exempt");
    apache.seed_bot("evilbot", "EvilBot");
    apache.stop_bots("add-exempt-path --site test.example --path /api/");
    apache.stop_bots("add-exempt-path --site test.example --path /dav/ --user-agent okhttp");
    apache.stop_bots("add-trusted --user-agent UptimeMonitor");
    apache.apply();

    // An exempt path reaches the site, which has nothing there.
    assert_eq!(apache.status("/api/x", BAD_AGENT), "404");
    // A `..` cannot walk out of it: the path is matched resolved.
    assert_eq!(
        apache.status("/api/../index.html", "--path-as-is -A EvilBot"),
        "403"
    );
    // An agent exemption needs the agent and the path.
    assert_eq!(apache.status("/dav/x", "-A 'EvilBot okhttp/4'"), "404");
    assert_eq!(apache.status("/", "-A 'EvilBot okhttp/4'"), "403");
    assert_eq!(apache.status("/dav/x", BAD_AGENT), "403");
    // A trusted user agent gets through whatever else it matches.
    assert_eq!(apache.status("/", "-A 'EvilBot UptimeMonitor'"), "200");
    assert_eq!(apache.status("/", BAD_AGENT), "403");

    apache.stop_bots("add-trusted --address 127.0.0.1");
    apache.apply();
    assert_eq!(apache.status("/", BAD_AGENT), "200", "a trusted address");
}

#[test]
fn apache_turns_away_requests_by_their_shape() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-shape");
    apache.stop_bots("set-site-rule --site test.example --rule no-accept --enabled true");
    apache.stop_bots("set-site-rule --site test.example --rule ip-literal-host --enabled true");
    apache.apply();

    assert_eq!(
        apache.status(
            "/",
            &format!("{BROWSER} -H 'Host: test.example' -H 'Accept:'")
        ),
        "403"
    );
    assert_eq!(
        apache.status("/", &format!("{BROWSER} -H 'Host: test.example'")),
        "200"
    );
    // curl sends `Host: 127.0.0.1:8080` unless told otherwise.
    assert_eq!(apache.status("/", BROWSER), "403");
    // ACME's path is never turned away by a shape rule.
    assert_eq!(
        apache.status("/.well-known/acme-challenge/x", "-H 'Accept:'"),
        "404"
    );
}

#[test]
fn apache_without_mod_rewrite_refuses_and_puts_everything_back() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-norewrite");
    apache.sh("a2dismod -q -f rewrite && apache2ctl graceful");
    let before = apache.sh(&format!("cat {APACHE_SITE}"));
    apache.seed_bot("evilbot", "EvilBot");

    let (ok, stdout, stderr) = apache.run("stop-bots apply-blocks --db /tmp/db.sqlite3");
    let said = format!("{stdout}{stderr}");
    assert!(!ok, "the apply succeeded without mod_rewrite:\n{said}");
    assert!(said.contains("a2enmod rewrite"), "the apply said:\n{said}");
    assert_eq!(apache.sh(&format!("cat {APACHE_SITE}")), before);
    let status = apache.stop_bots("status --quiet || true");
    assert!(status.contains("a2enmod rewrite"), "status said:\n{status}");
}

#[test]
fn apache_uninstall_puts_the_site_back_byte_for_byte() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-uninstall");
    let original = apache.sh(&format!("cat {APACHE_SITE}"));
    apache.seed_bot("evilbot", "EvilBot");
    apache.stop_bots("set-robots-txt --enabled true");
    apache.stop_bots("add-trusted --user-agent UptimeMonitor");
    apache.apply();
    apache.sh("test -f /etc/apache2/conf-enabled/stop-bots-trusted.conf");
    apache.sh("test -f /etc/stop-bots/apache/robots.txt");

    let said = apache.stop_bots("uninstall nginx");
    assert_eq!(
        apache.sh(&format!("cat {APACHE_SITE}")),
        original,
        "uninstall said:\n{said}"
    );
    apache.sh("test ! -e /etc/apache2/conf-enabled/stop-bots-trusted.conf");
    apache.sh("test ! -e /etc/stop-bots/apache/robots.txt");
    let (ok, stdout, stderr) = apache.run("apache2ctl configtest");
    assert!(ok, "Apache's config no longer loads:\n{stdout}{stderr}");
    std::thread::sleep(std::time::Duration::from_millis(700));
    assert_eq!(apache.status("/", BAD_AGENT), "200");
}

#[test]
fn apache_access_log_is_read_by_the_detectors() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-log");
    // Through mod_remoteip, so Apache logs a public client; see
    // `Dockerfile.apache`.
    let from = |address: &str| format!("-H 'X-Forwarded-For: {address}'");
    apache.status(
        "/",
        &format!("{} -A 'ApacheLogProbe/1.0'", from("203.0.113.9")),
    );
    apache.status("/.env", &from("203.0.113.10"));

    // Read from Apache's own log, because the host settings chose Apache.
    let recorded = apache.stop_bots("record-access-stats");
    let stats = apache.stop_bots("list-access-stats");
    assert!(
        stats.contains("ApacheLogProbe/1.0"),
        "record-access-stats said:\n{recorded}\nlist-access-stats said:\n{stats}"
    );
    let detected = apache.stop_bots("run-detector probe-paths");
    let rules = apache.stop_bots("list-firewall-rules");
    assert!(
        rules.contains("203.0.113.10") && !rules.contains("203.0.113.9"),
        "run-detector probe-paths said:\n{detected}\nlist-firewall-rules said:\n{rules}"
    );
}

impl Apache {}

/// Polls `status` until it is `want`, for up to five seconds: a graceful
/// restart is asynchronous, and an old child can still answer first.
fn eventually(want: &str, status: impl Fn() -> String) -> String {
    let mut got = String::new();
    for _ in 0..50 {
        got = status();
        if got == want {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    got
}

// ---- Apache: sites as operators write them ----

impl Apache {
    /// Writes `conf` as a site of its own, enables it, restarts Apache
    /// gracefully and scans again. The image listens on 8081-8084 for
    /// these; a TLS site brings its own `Listen`.
    fn add_site(&self, name: &str, conf: &str) {
        self.sh(&format!(
            "cat > /etc/apache2/sites-available/{name}.conf <<'CONF'\n{conf}CONF\n\
             a2ensite -q {name} && apache2ctl configtest && apache2ctl graceful"
        ));
        std::thread::sleep(std::time::Duration::from_millis(700));
        self.wait_until_serving();
        self.stop_bots("scan-sites");
    }

    /// The status `url` answers with for `host`, `000` for no answer.
    fn status_at(&self, url: &str, host: &str, curl_args: &str) -> String {
        let (_, stdout, _) = self.run(&format!(
            "curl -sk -o /dev/null -w '%{{http_code}}' -H 'Host: {host}' {curl_args} {url}"
        ));
        stdout.trim().to_string()
    }

    fn body_at(&self, url: &str, host: &str, curl_args: &str) -> String {
        self.run(&format!("curl -sk -H 'Host: {host}' {curl_args} {url}"))
            .1
    }
}

/// One file holding a plain host, a TLS one inside `<IfModule mod_ssl.c>`
/// as certbot and Debian's `default-ssl` write it, and a second site: each
/// gets a block of its own.
const MULTI_SITE: &str = "\
<VirtualHost *:8081>
    ServerName multi.example
    DocumentRoot /var/www/test
</VirtualHost>

<IfModule mod_ssl.c>
Listen 8443
<VirtualHost *:8443>
    ServerName multi.example
    DocumentRoot /var/www/test
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
</VirtualHost>
</IfModule>

<VirtualHost *:8081>
    ServerName other.example
    DocumentRoot /var/www/test
</VirtualHost>
";

#[test]
fn apache_blocks_in_every_host_of_a_file_the_tls_one_included() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-multi");
    apache.add_site("multi", MULTI_SITE);
    apache.seed_bot("evilbot", "EvilBot");
    apache.apply();

    for (url, host) in [
        ("http://127.0.0.1:8081/", "multi.example"),
        ("https://127.0.0.1:8443/", "multi.example"),
        ("http://127.0.0.1:8081/", "other.example"),
    ] {
        assert_eq!(
            apache.status_at(url, host, BAD_AGENT),
            "403",
            "{host} at {url}"
        );
        assert_eq!(
            apache.status_at(url, host, BROWSER),
            "200",
            "{host} at {url}"
        );
    }
    let file = apache.sh("cat /etc/apache2/sites-available/multi.conf");
    assert_eq!(
        file.matches("# BEGIN stop-bots").count(),
        3,
        "file:\n{file}"
    );
}

/// The TLS rule a host without HTTP/2 must never get: every visitor is
/// HTTP/1.1 there. Refused until `a2enmod http2`, then turns HTTP/1.1 away
/// and lets HTTP/2 through.
#[test]
fn apache_writes_the_http_1x_rule_only_once_http2_is_on() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-http2");
    apache.add_site("multi", MULTI_SITE);
    apache.stop_bots("set-site-rule --site multi.example --rule http-1x --enabled true");
    let before = apache.sh("cat /etc/apache2/sites-available/multi.conf");

    let (ok, stdout, stderr) = apache.run("stop-bots apply-blocks --db /tmp/db.sqlite3");
    assert!(!ok, "applied without HTTP/2:\n{stdout}{stderr}");
    assert!(stderr.contains("HTTP/1.x"), "said:\n{stderr}");
    assert_eq!(
        apache.sh("cat /etc/apache2/sites-available/multi.conf"),
        before
    );

    apache.sh("a2enmod -q http2 && apache2ctl graceful");
    apache.apply();
    let tls = "https://127.0.0.1:8443/";
    assert_eq!(
        eventually("403", || apache.status_at(
            tls,
            "multi.example",
            "--http1.1"
        )),
        "403"
    );
    assert_eq!(apache.status_at(tls, "multi.example", "--http2"), "200");
    // The port-80 host never gets it: everything there is HTTP/1.1.
    assert_eq!(
        apache.status_at("http://127.0.0.1:8081/", "multi.example", BROWSER),
        "200"
    );
}

/// `ProxyPass /` answers the translate phase too; an `Alias` lost to it,
/// and the site served the backend's robots.txt, or nothing. Nothing
/// listens on port 9, so whatever is proxied is a 503.
#[test]
fn apache_serves_robots_txt_on_a_site_that_proxies_everything() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-proxied");
    apache.add_site(
        "proxied",
        "<VirtualHost *:8082>\n    ServerName proxied.example\n    ProxyPass / http://127.0.0.1:9/\n</VirtualHost>\n",
    );
    apache.seed_bot("evilbot", "EvilBot");
    apache.stop_bots("set-robots-txt --enabled true");
    apache.apply();

    let site = "http://127.0.0.1:8082";
    assert_eq!(
        apache.status_at(&format!("{site}/"), "proxied.example", BROWSER),
        "503",
        "the site does not proxy"
    );
    let robots = apache.body_at(&format!("{site}/robots.txt"), "proxied.example", BAD_AGENT);
    assert!(
        robots.contains("User-agent: EvilBot"),
        "robots.txt:\n{robots}"
    );
    assert_eq!(
        apache.status_at(&format!("{site}/"), "proxied.example", BAD_AGENT),
        "403"
    );
}

/// A WordPress-style front controller: `.htaccess` sends every path that
/// is not a file on to one page, an internal redirect on which the
/// vhost's rules run again with the new path. The decision made on the
/// path the client asked for must stand.
const FRONT_CONTROLLER_SITE: &str = "\
<VirtualHost *:8083>
    ServerName wp.example
    DocumentRoot /var/www/wp
    ErrorDocument 403 /blocked.html
    <Directory /var/www/wp>
        AllowOverride All
    </Directory>
</VirtualHost>
";

fn with_front_controller(apache: &Apache) {
    apache.sh(
        "mkdir -p /var/www/wp && echo front > /var/www/wp/index.html && \
         echo 'turned away' > /var/www/wp/blocked.html && \
         printf '%s\\n' 'RewriteEngine On' 'RewriteBase /' \
             'RewriteCond %{REQUEST_FILENAME} !-f' 'RewriteCond %{REQUEST_FILENAME} !-d' \
             'RewriteRule . /index.html [L]' > /var/www/wp/.htaccess",
    );
    apache.add_site("wp", FRONT_CONTROLLER_SITE);
}

#[test]
fn apache_keeps_an_exempt_path_exempt_through_a_front_controller() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-frontctl");
    with_front_controller(&apache);
    apache.seed_bot("evilbot", "EvilBot");
    apache.stop_bots("add-exempt-path --site wp.example --path /wp-json/");
    apache.apply();

    let site = "http://127.0.0.1:8083";
    let (status, body) = (
        apache.status_at(
            &format!("{site}/wp-json/wp/v2/posts"),
            "wp.example",
            BAD_AGENT,
        ),
        apache.body_at(
            &format!("{site}/wp-json/wp/v2/posts"),
            "wp.example",
            BAD_AGENT,
        ),
    );
    assert_eq!((status.as_str(), body.trim()), ("200", "front"));
    // Everything else still turns the bot away.
    assert_eq!(
        apache.status_at(&format!("{site}/about/"), "wp.example", BAD_AGENT),
        "403"
    );
}

#[test]
fn apache_lets_a_trusted_client_through_a_front_controller() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-frontctl-trust");
    with_front_controller(&apache);
    apache.seed_bot("evilbot", "EvilBot");
    apache.stop_bots("add-trusted --user-agent UptimeMonitor");
    apache.apply();

    let page = "http://127.0.0.1:8083/about/";
    assert_eq!(
        apache.status_at(page, "wp.example", "-A 'EvilBot UptimeMonitor'"),
        "200"
    );
    assert_eq!(apache.status_at(page, "wp.example", BAD_AGENT), "403");
}

/// A blocked request's own error page is an internal redirect too, and
/// must be served, not blocked in turn.
#[test]
fn apache_serves_a_blocked_request_its_error_document() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-errordoc");
    with_front_controller(&apache);
    apache.seed_bot("evilbot", "EvilBot");
    apache.apply();

    let page = "http://127.0.0.1:8083/";
    assert_eq!(apache.status_at(page, "wp.example", BAD_AGENT), "403");
    let body = apache.body_at(page, "wp.example", BAD_AGENT);
    assert_eq!(body.trim(), "turned away", "the error page was:\n{body}");
}

/// The config test passes a block a later `RewriteEngine Off` switches
/// off; the apply refuses it, and the site keeps serving as it was.
#[test]
fn apache_refuses_a_site_that_switches_rewriting_off() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-rewrite-off");
    apache.add_site(
        "off",
        "<VirtualHost *:8081>\n    ServerName off.example\n    DocumentRoot /var/www/test\n    RewriteEngine Off\n</VirtualHost>\n",
    );
    apache.seed_bot("evilbot", "EvilBot");

    let (ok, stdout, stderr) = apache.run("stop-bots apply-blocks --db /tmp/db.sqlite3");
    assert!(!ok, "applied anyway:\n{stdout}{stderr}");
    assert!(stderr.contains("RewriteEngine Off"), "said:\n{stderr}");
    let file = apache.sh("cat /etc/apache2/sites-available/off.conf");
    assert!(!file.contains("stop-bots"), "file:\n{file}");
}

/// The NGINX finding's table under a real Apache: blocked user agents with
/// a backslash, a quote, a brace or a `$` in them, stored as a release
/// that took them wrote them, each turn away exactly that client — and not
/// the near miss beside it, a browser, curl or Googlebot.
///
/// Apache reads these through two parsers NGINX does not have:
/// `mod_rewrite`'s own argument splitting, where nothing escapes a quote,
/// and the core's `${NAME}` substitution, which runs on every line before
/// any module sees it. So a few rows of its own ride along: a `${...}`
/// that names a variable Apache defines, a `%{...}` that `mod_rewrite`
/// expands in a test string, and agents that start with what it would read
/// as a negation or a string comparison rather than a regex. Each of those, read the other way, either refuses everyone or
/// no one.
#[test]
fn apache_blocks_hostile_stored_agents_exactly_their_client() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-hostile");
    const APACHE_ONLY: [(&str, Option<&str>); 4] = [
        (
            "Scraper/2.1 ${APACHE_LOG_DIR}",
            Some("Scraper/2.1 /var/log/apache2"),
        ),
        (
            "Scraper/2.1 %{HTTP_HOST}",
            Some("Scraper/2.1 127.0.0.1:8080"),
        ),
        ("!Scraper/2.1", None),
        ("=Scraper/2.1", None),
    ];
    let hostile: Vec<_> = HOSTILE_USER_AGENTS.iter().chain(&APACHE_ONLY).collect();

    let mut sql = String::new();
    for (user_agent, _) in &hostile {
        sql.push_str(&format!(
            "INSERT INTO blocked_user_agents (user_agent, blocked_at) VALUES ('{}', 0);\n",
            user_agent.replace('\'', "''")
        ));
    }
    for path in [r"/x\|", r"/x\("] {
        sql.push_str(&format!(
            "INSERT INTO site_path_exemptions (site_id, path) \
             SELECT id, '{path}' FROM sites WHERE server_name = 'test.example';\n"
        ));
    }
    apache.sh(&format!("sqlite3 /tmp/db.sqlite3 <<'SQL'\n{sql}SQL"));
    let json = r#"[{"id":"listed","categories":["ai"],"pattern":{"accepted":["ListedBot","Bot[z-a]x","Botx{2,1}","Botx{99999}"],"forbidden":[]}}]"#;
    apache.sh(&format!("cat > /tmp/bots.json <<'JSON'\n{json}\nJSON"));
    apache.stop_bots("update-bot-lists --source /tmp/bots.json");
    apache.apply();

    let site = apache.sh(&format!("cat {APACHE_SITE}"));
    let status = |user_agent: &str| apache.status("/", &format!("-A {}", sh_quoted(user_agent)));
    for (user_agent, near_miss) in &hostile {
        assert_eq!(
            status(user_agent),
            "403",
            "{user_agent:?} was served. site:\n{site}"
        );
        if let Some(near_miss) = near_miss {
            assert_eq!(
                status(near_miss),
                "200",
                "{near_miss:?} was refused by the rule for {user_agent:?}. site:\n{site}"
            );
        }
    }
    assert_eq!(
        status("ListedBot/1.0"),
        "403",
        "the list's good pattern was lost"
    );
    for ordinary in [
        "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
        "curl/8.14.1",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    ] {
        assert_eq!(
            status(ordinary),
            "200",
            "{ordinary:?} was refused. site:\n{site}"
        );
    }
}

/// A rule set for one site is enforced there and not on the site beside
/// it: each `<VirtualHost>` gets its own block, written from its own
/// settings.
#[test]
fn apache_enforces_a_per_site_rule_on_that_site_and_not_its_neighbour() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-two-sites");
    apache.add_site(
        "other",
        "<VirtualHost *:8081>\n    ServerName other.example\n    DocumentRoot /var/www/test\n</VirtualHost>\n",
    );
    let no_ua = "-H 'Accept: text/html' -H 'Accept-Language: en' -A ''";
    let other = || apache.status_at("http://127.0.0.1:8081/", "other.example", no_ua);
    assert_eq!(
        apache.status("/", no_ua),
        "200",
        "the site serves before the rule"
    );
    assert_eq!(other(), "200", "its neighbour serves before the rule");

    apache.stop_bots("set-site-rule --site test.example --rule no-user-agent --enabled true");
    apache.apply();

    assert_eq!(
        apache.status("/", no_ua),
        "403",
        "the rule did not take effect on the site it was set for"
    );
    assert_eq!(
        other(),
        "200",
        "a rule set for one site is being enforced on its neighbour"
    );
}

/// An agent exemption lets its one client through on its one path, and no
/// further: not off the path, not by walking out of it, and not another
/// bot on it.
#[test]
fn apache_serves_an_agent_exemption_only_its_client_on_only_its_paths() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-agent-exempt");
    apache.seed_bot("okhttp", "okhttp");
    apache.seed_bot("badbot", "BadBot");
    apache.stop_bots("add-exempt-path --site test.example --path /dav/ --user-agent okhttp");
    apache.apply();

    for (path, user_agent, expected, why) in [
        (
            "/dav/file",
            "okhttp/4.10.0",
            "404",
            "the exempt client on its path",
        ),
        (
            "/DAV/file",
            "okhttp/4.10.0",
            "404",
            "the path, matched without case",
        ),
        (
            "/",
            "okhttp/4.10.0",
            "403",
            "the exempt client off its path",
        ),
        (
            "/dav/../index.html",
            "okhttp/4.10.0",
            "403",
            "walking out with ..",
        ),
        (
            "/dav/%2e%2e/index.html",
            "okhttp/4.10.0",
            "403",
            "walking out with %2e%2e",
        ),
        (
            "/dav/file",
            "BadBot/1.0",
            "403",
            "another bot on the exempt path",
        ),
        ("/", "Mozilla/5.0", "200", "an ordinary visitor"),
    ] {
        assert_eq!(
            apache.status(path, &format!("--path-as-is -A '{user_agent}'")),
            expected,
            "{why}: {user_agent} on {path}"
        );
    }
}

// ---- upgrading a real 0.1.1 install ----
//
// The release that added Apache moved NGINX behind the layer both servers
// share, and promises an NGINX host nothing to do: the same database, the
// same files, and only a site with an exemption reading as stale until it
// is applied again. These start from what the released 0.1.1 binary
// actually left on a host, not from a fixture of it.

/// The systemd host with the 0.1.1 binary beside the one under test — see
/// `Dockerfile.upgrade`.
fn upgrade_image() -> String {
    tagged("stop-bots-upgrade")
}

fn build_upgrade_image() {
    build_host_image();
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        with_build_lock(|| {
            build_unless_current(&upgrade_image(), || {
                let ctx = stage_binary();
                let out = Command::new(runtime())
                    .args(["build", "-q", "-f", &format!("{ctx}/Dockerfile.upgrade")])
                    .args(["--build-arg", &format!("BASE={}", host_image())])
                    .args(["-t", &upgrade_image(), &ctx])
                    .output()
                    .expect("failed to run the image build");
                assert!(
                    out.status.success(),
                    "{} build (upgrade image) failed:\n{}",
                    runtime(),
                    String::from_utf8_lossy(&out.stderr)
                );
            });
        });
    });
}

/// What the changelog tells a host that had the web console installed
/// to run after upgrading, before anything else, as root. Kept here, run
/// by the tests below exactly as written, so the instructions are known
/// to leave nothing behind.
const REMOVE_THE_CONSOLE: &str = "\
systemctl disable --now stop-bots-web.service stop-bots-helper.socket
systemctl stop stop-bots-helper.service
rm -f /etc/systemd/system/stop-bots-web.service \\
  /etc/systemd/system/stop-bots-helper.socket \\
  /etc/systemd/system/stop-bots-helper.service
systemctl daemon-reload
chown -R root:root /var/lib/stop-bots
userdel stop-bots
";

/// The sites the upgrade test serves, by file and port: the suite's own,
/// with a request-shape rule; a second with an exempt path; and a third
/// with neither. The release changes the block of the first two, both of
/// which exempt a path (a request rule always exempts `/.well-known/`),
/// and not the third's.
const UPGRADE_SITES: [(&str, u16); 3] = [
    ("test-site.conf", 8080),
    ("other-site.conf", 8081),
    ("plain-site.conf", 8082),
];

impl Host {
    /// A host that 0.1.1 set up, as an operator following its README would
    /// have: the console installed as a service, the three sites of
    /// [`UPGRADE_SITES`] scanned, a bot blocked, a per-site rule and an
    /// exemption set, the blocks applied and a firewall rule loaded. The
    /// binary under test is kept aside, at `/root/stop-bots-new`, for the
    /// upgrade.
    fn set_up_by_0_1_1(name: &str) -> Host {
        build_upgrade_image();
        let host = Host::boot_image(name, &upgrade_image(), None);
        host.sh("cp /usr/local/bin/stop-bots /root/stop-bots-new \
             && install -m 755 /usr/local/bin/stop-bots-0.1.1 /usr/local/bin/stop-bots");
        assert!(
            host.sh("stop-bots --version").contains("0.1.1"),
            "the host is not running 0.1.1"
        );
        for (name, port) in [("other", 8081), ("plain", 8082)] {
            host.sh(&format!(
                "printf 'server {{\\n    listen {port};\\n    server_name {name}.example;\\n    \
                 root /var/www/test;\\n    index index.html;\\n    \
                 location / {{ try_files $uri $uri/ =404; }}\\n}}\\n' \
                 > /etc/nginx/sites-enabled/{name}-site.conf"
            ));
        }
        host.sh("systemctl start nginx");
        // The console as 0.1.1's README set it up, which is how the hosts
        // that are upgraded have it.
        host.sh("stop-bots install web");
        host.wait_until_active("stop-bots-web.service");
        host.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
        host.seed_bot("evilbot", "EvilBot");
        host.stop_bots(
            "set-site-rule --site test.example --rule no-accept-language --enabled true",
        );
        // 0.1.1's spelling: this is 0.1.1 running.
        host.stop_bots("exempt-path --site other.example --path /wp-json/");
        host.stop_bots("apply-blocks");
        host.stop_bots("add-firewall-rule --address 203.0.113.50");
        // An SSH log with nobody in it, for the lockout check to read: with
        // none at all it rightly refuses to apply.
        host.sh("touch /var/log/auth.log");
        host.stop_bots("render-firewall --apply --ssh-log /var/log/auth.log");
        host
    }

    /// Upgrades the way the changelog says to: the binary replaced, as a
    /// package upgrade replaces it, then [`REMOVE_THE_CONSOLE`] run as
    /// written, then `install cron`. Asserts nothing of the console is
    /// left: no unit, no user, nothing listening.
    fn upgrade_to_the_binary_under_test(&self) {
        self.sh("install -m 755 /root/stop-bots-new /usr/local/bin/stop-bots");
        assert!(
            !self.sh("stop-bots --version").contains("0.1.1"),
            "the binary was not replaced"
        );
        self.sh(&format!("set -e\n{REMOVE_THE_CONSOLE}"));
        self.sh("stop-bots install cron");

        let units = self.sh("ls /etc/systemd/system");
        assert!(
            !units.contains("stop-bots-web") && !units.contains("stop-bots-helper"),
            "a console unit is left:\n{units}"
        );
        assert!(!self.run("id stop-bots").0, "the console's user is left");
        assert!(
            !self.run("ss -ltn | grep -q ':8787 '").0,
            "something still listens on the console's port"
        );
    }

    /// Waits up to 30s for `unit` to be active.
    fn wait_until_active(&self, unit: &str) {
        for _ in 0..300 {
            if self.run(&format!("systemctl is-active --quiet {unit}")).0 {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("{unit} never started:\n{}", self.journal(unit));
    }

    /// What upgrading must not touch by itself: every site file by hash,
    /// and the loaded ruleset.
    fn what_is_enforced(&self) -> String {
        self.sh("sha256sum /etc/nginx/sites-enabled/* && nft list ruleset")
    }

    /// The status `site` on `port` answers `/`-relative `path` with.
    fn status_at(&self, port: u16, path: &str, curl_args: &str) -> String {
        self.run(&format!(
            "curl -s -o /dev/null -w '%{{http_code}}' {curl_args} http://127.0.0.1:{port}{path}"
        ))
        .1
        .trim()
        .to_string()
    }
}

/// **Upgrading changes nothing by itself, and tells the truth about what
/// the next apply will change.** The host 0.1.1 set up keeps every site
/// file and its loaded ruleset byte for byte across the upgrade, keeps its
/// host settings free of a `web_server` line, and the sites `status` calls
/// not applied are exactly the sites the next apply then rewrites.
///
/// Which sites those are depends on the release: one that changes the
/// block's shape changes the sites that exempt a path, and one whose
/// built-in list grew changes them all. So the test compares the two
/// rather than naming either.
#[test]
fn upgrading_a_0_1_1_nginx_host_changes_nothing_until_it_is_applied() {
    if !enabled() {
        return;
    }
    let host = Host::set_up_by_0_1_1("stop-bots-upgrade-untouched");
    let before = host.what_is_enforced();

    host.upgrade_to_the_binary_under_test();

    assert_eq!(
        host.what_is_enforced(),
        before,
        "upgrading changed a site or the loaded rules by itself"
    );
    let settings = host.sh("cat /etc/stop-bots/host.conf");
    assert!(
        !settings.contains("web_server"),
        "an NGINX host got a web_server line, which 0.1.1 refuses:\n{settings}"
    );
    let status = host
        .run_uncontended(&format!("stop-bots status --db {HOST_DB}"))
        .1;
    let not_applied: std::collections::BTreeSet<String> = status
        .lines()
        .find_map(|line| line.split_once("site(s) not applied: "))
        .map(|(_, names)| {
            names
                .split(", ")
                .map(|name| name.trim().to_string())
                .collect()
        })
        .unwrap_or_default();

    let hash = |file: &str| host.sh(&format!("sha256sum /etc/nginx/sites-enabled/{file}"));
    let hashes: Vec<String> = UPGRADE_SITES.iter().map(|(file, _)| hash(file)).collect();
    host.stop_bots("apply-blocks");
    let rewritten: std::collections::BTreeSet<String> = UPGRADE_SITES
        .iter()
        .zip(&hashes)
        .filter(|((file, _), before)| hash(file) != **before)
        .map(|((file, _), _)| format!("{}.example", file.trim_end_matches("-site.conf")))
        .collect();
    assert!(
        !rewritten.is_empty(),
        "the release changed no site's block, so this proves nothing"
    );
    assert_eq!(
        not_applied, rewritten,
        "status's not-applied sites are not the ones the apply rewrote. status:\n{status}"
    );
}

/// **After the upgrade, an apply from the CLI enforces every setting
/// 0.1.1 stored.** The per-site rule, the
/// blocked bot and the exemption all hold on the sites they were set for,
/// both sites read as applied, and the firewall rule is still there.
#[test]
fn a_0_1_1_nginx_host_applies_what_it_had_after_the_upgrade() {
    if !enabled() {
        return;
    }
    let host = Host::set_up_by_0_1_1("stop-bots-upgrade-applies");
    host.upgrade_to_the_binary_under_test();

    host.stop_bots("apply-blocks");
    let status = host
        .run_uncontended(&format!("stop-bots status --db {HOST_DB}"))
        .1;
    assert!(
        status.contains("3 site(s) applied"),
        "the sites do not read as applied:\n{status}"
    );

    let bot = "-A 'Mozilla/5.0 (compatible; EvilBot/1.0)'";
    let browser = "-A 'Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0' -H 'Accept-Language: en'";
    for (port, path, curl_args, expected, why) in [
        (8080, "/", bot, "403", "the blocked bot, on the first site"),
        (8081, "/", bot, "403", "the blocked bot, on the second"),
        (
            8081,
            "/wp-json/",
            bot,
            "404",
            "the blocked bot, on the exempt path",
        ),
        (8080, "/", browser, "200", "a browser"),
        (
            8080,
            "/",
            "-A 'Mozilla/5.0'",
            "403",
            "no Accept-Language, where the rule is on",
        ),
        (
            8081,
            "/",
            "-A 'Mozilla/5.0'",
            "200",
            "no Accept-Language, where it is off",
        ),
    ] {
        assert_eq!(
            eventually(expected, || host.status_at(port, path, curl_args)),
            expected,
            "{why}"
        );
    }
    let rules = host.stop_bots("list-firewall-rules");
    assert!(
        rules.contains("203.0.113.50"),
        "the firewall rule 0.1.1 stored is gone:\n{rules}"
    );
}

/// **An NGINX host can still go back to 0.1.1, through the backup** the
/// upgrade made. This release adds to the database's schema, which 0.1.1
/// refuses to open rather than misread, and leaves the site files alone
/// when it does. The upgrade kept the database as it was beside it
/// (`.bak-v6`); with that put back, 0.1.1 recognises the blocks the new
/// release wrote and replaces them rather than adding a second, and NGINX
/// loads the result.
#[test]
fn a_0_1_1_nginx_host_can_go_back_through_the_pre_upgrade_backup() {
    if !enabled() {
        return;
    }
    let host = Host::set_up_by_0_1_1("stop-bots-upgrade-back");
    host.upgrade_to_the_binary_under_test();
    host.stop_bots("apply-blocks");
    let sites_before: Vec<String> = UPGRADE_SITES
        .iter()
        .map(|(file, _)| host.sh(&format!("cat /etc/nginx/sites-enabled/{file}")))
        .collect();

    host.sh("install -m 755 /usr/local/bin/stop-bots-0.1.1 /usr/local/bin/stop-bots");
    let (ok, stdout, stderr) = host.run(&format!("stop-bots apply-blocks --db {HOST_DB}"));
    assert!(
        !ok,
        "0.1.1 opened a database with a newer schema:\n{stdout}{stderr}"
    );
    for ((file, _), before) in UPGRADE_SITES.iter().zip(&sites_before) {
        let after = host.sh(&format!("cat /etc/nginx/sites-enabled/{file}"));
        assert_eq!(&after, before, "0.1.1's refusal changed {file}");
    }

    host.sh(&format!("cp {HOST_DB}.bak-v6 {HOST_DB}"));
    let (ok, stdout, stderr) = host.run(&format!("stop-bots apply-blocks --db {HOST_DB}"));
    assert!(
        ok,
        "0.1.1 cannot apply with the pre-upgrade database put back:\n{stdout}{stderr}"
    );
    for (file, _) in UPGRADE_SITES {
        let site = host.sh(&format!("cat /etc/nginx/sites-enabled/{file}"));
        assert_eq!(
            site.matches("# BEGIN stop-bots").count(),
            1,
            "{file} does not hold exactly one block:\n{site}"
        );
    }
    let (valid, out, err) = host.run("nginx -t");
    assert!(
        valid,
        "NGINX does not load what 0.1.1 wrote back:\n{out}{err}"
    );
    for (file, port) in UPGRADE_SITES {
        assert_eq!(
            eventually("403", || host.status_at(
                port,
                "/",
                "-A 'Mozilla/5.0 (compatible; EvilBot/1.0)'"
            )),
            "403",
            "{file} no longer blocks the bot under 0.1.1"
        );
    }
}

// ---- Apache as RHEL lays it out ----

fn rhel_image() -> String {
    tagged("stop-bots-rhel")
}

fn build_rhel_image() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        with_build_lock(|| {
            build_unless_current(&rhel_image(), || {
                let ctx = stage_binary();
                let out = Command::new(runtime())
                    .args(["build", "-q", "-f", &format!("{ctx}/Dockerfile.rhel")])
                    .args(["-t", &rhel_image(), &ctx])
                    .output()
                    .expect("failed to run the image build");
                assert!(
                    out.status.success(),
                    "{} build (RHEL image) failed:\n{}",
                    runtime(),
                    String::from_utf8_lossy(&out.stderr)
                );
            });
        });
    });
}

/// The site file, where RHEL keeps every site: in `conf.d`.
const RHEL_SITE: &str = "/etc/httpd/conf.d/test-site.conf";

impl Apache {
    /// A running `httpd` with RHEL's tree, and stop-bots told it is Apache
    /// rooted at `/etc/httpd` — and nothing else, which is all an operator
    /// there has to say: the commands follow the tree.
    fn start_rhel(name: &str) -> Apache {
        build_rhel_image();
        let name = scoped(name);
        remove_container(&name);
        let out = Command::new(runtime())
            .args(["run", "-d", "--name", &name, &rhel_image()])
            .output()
            .expect("failed to start the container");
        assert!(
            out.status.success(),
            "{} run failed:\n{}",
            runtime(),
            String::from_utf8_lossy(&out.stderr)
        );
        let apache = Apache { name };
        apache.sh("httpd -k start");
        apache.wait_until_serving();
        let chosen = apache.stop_bots("set-web-server apache --root /etc/httpd");
        for command in ["apachectl configtest", "systemctl reload httpd"] {
            assert!(
                chosen.contains(command),
                "RHEL's tree does not default to `{command}`:\n{chosen}"
            );
        }
        let scanned = apache.stop_bots("scan-sites");
        assert!(
            scanned.contains("Discovered 1 site(s)"),
            "scan-sites said:\n{scanned}"
        );
        apache
    }

    /// `apply-blocks`, then a wait for the graceful restart; RHEL's
    /// [`Self::apply`].
    fn apply_rhel(&self) -> String {
        let said = self.stop_bots("apply-blocks");
        let (ok, stdout, stderr) = self.run("apachectl configtest");
        assert!(ok, "the generated config does not load:\n{stdout}{stderr}");
        std::thread::sleep(std::time::Duration::from_millis(700));
        self.wait_until_serving();
        said
    }
}

/// **On RHEL's tree, the block lands in the site in `conf.d`, the files it
/// needs land in `conf.d` where `httpd.conf` reads them, `httpd` enforces
/// it, and uninstalling puts the site back byte for byte.**
#[test]
fn apache_on_rhel_blocks_from_conf_d_and_uninstalls_cleanly() {
    if !enabled() {
        return;
    }
    let apache = Apache::start_rhel("sb-apache-rhel");
    let original = apache.sh(&format!("cat {RHEL_SITE}"));
    apache.seed_bot("evilbot", "EvilBot");
    apache.stop_bots("set-robots-txt --enabled true");
    apache.stop_bots("add-trusted --user-agent 'EvilBot-Monitor'");
    apache.apply_rhel();

    let site = apache.sh(&format!("cat {RHEL_SITE}"));
    assert!(site.contains("# BEGIN stop-bots"), "site file:\n{site}");
    let conf_d = apache.sh("ls /etc/httpd/conf.d");
    assert!(
        conf_d.contains("stop-bots-trusted.conf"),
        "the trust file is not in conf.d:\n{conf_d}"
    );
    for (curl_args, expected, why) in [
        (BAD_AGENT, "403", "the blocked bot"),
        (
            "-A 'EvilBot-Monitor/2.0'",
            "200",
            "the trusted client it resembles",
        ),
        (BROWSER, "200", "a browser"),
    ] {
        assert_eq!(apache.status("/", curl_args), expected, "{why}");
    }
    assert!(
        apache.body("/robots.txt", BAD_AGENT).contains("EvilBot"),
        "robots.txt is not the generated one"
    );

    let said = apache.stop_bots("uninstall web-server");
    assert_eq!(
        apache.sh(&format!("cat {RHEL_SITE}")),
        original,
        "uninstall said:\n{said}"
    );
    apache.sh("test ! -e /etc/httpd/conf.d/stop-bots-trusted.conf");
    let (ok, stdout, stderr) = apache.run("apachectl configtest");
    assert!(ok, "httpd's config no longer loads:\n{stdout}{stderr}");
}

/// **The detectors read what RHEL's `httpd` logs, with nothing named.**
/// The site logs to the relative `logs/access_log`, which is
/// `/var/log/httpd/access_log` through the `logs` link — RHEL's stock
/// access log, the default in its tree.
#[test]
fn apache_on_rhel_detects_from_httpds_access_log() {
    if !enabled() {
        return;
    }
    let apache = Apache::start_rhel("sb-apache-rhel-log");
    let from = |address: &str| format!("-H 'X-Forwarded-For: {address}'");
    apache.status(
        "/",
        &format!("{} -A 'RhelLogProbe/1.0'", from("203.0.113.9")),
    );
    apache.status("/.env", &from("203.0.113.10"));
    assert!(
        apache
            .sh("cat /var/log/httpd/access_log")
            .contains("203.0.113.10"),
        "httpd did not log the client, so this proves nothing"
    );

    let detected = apache.stop_bots("run-detector probe-paths");
    let rules = apache.stop_bots("list-firewall-rules");
    assert!(
        rules.contains("203.0.113.10") && !rules.contains("203.0.113.9"),
        "run-detector probe-paths said:\n{detected}\nlist-firewall-rules said:\n{rules}"
    );
}

// ---- the old-browser list, under both servers ----

/// An old browser, a feature phone, and two browsers people run now.
const OLD_AND_NEW: [(&str, &str, &str); 4] = [
    (
        "Opera/9.80 (Windows NT 6.1; U; en) Presto/2.8.131 Version/11.11",
        "403",
        "Presto-era Opera",
    ),
    (
        "SonyEricssonT650i/R7AA Browser/NetFront/3.3 Profile/MIDP-2.0",
        "403",
        "a feature phone",
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:158.0) Gecko/20100101 Firefox/158.0",
        "200",
        "Firefox now",
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/140.0.0.0 Safari/537.36",
        "200",
        "Chrome now",
    ),
];

/// **Switched on, the list turns old browsers away under a real NGINX and
/// serves browsers people run**: its escaped literals reach PCRE as the
/// strings they are.
#[test]
fn nginx_turns_away_old_browsers_once_the_list_is_on() {
    if !enabled() {
        return;
    }
    let server = Server::start("stop-bots-old-browsers");
    server.stop_bots("scan-sites --root /etc/nginx/sites-enabled");
    server.stop_bots("set-old-browsers --enabled true");
    server.apply_and_reload();

    for (user_agent, expected, what) in OLD_AND_NEW {
        assert_eq!(
            server.status("/", &format!("-A {}", sh_quoted(user_agent))),
            expected,
            "{what}"
        );
    }
}

/// The same under a real Apache, through `mod_rewrite`'s own quoting.
#[test]
fn apache_turns_away_old_browsers_once_the_list_is_on() {
    if !enabled() {
        return;
    }
    let apache = Apache::start("sb-apache-old-browsers");
    apache.stop_bots("set-old-browsers --enabled true");
    apache.apply();

    for (user_agent, expected, what) in OLD_AND_NEW {
        assert_eq!(
            apache.status("/", &format!("-A {}", sh_quoted(user_agent))),
            expected,
            "{what}"
        );
    }
}

// ---- Traefik ----
//
// A real Traefik 3 reading the routers file stop-bots writes, through its
// file provider: what the generated rules turn away and let through, that
// Traefik loads every router of them, and that its log feeds the
// detectors. `Dockerfile.traefik` says how it is set up.

fn traefik_image() -> String {
    tagged("stop-bots-traefik")
}

fn build_traefik_image() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        with_build_lock(|| {
            build_unless_current(&traefik_image(), || {
                let ctx = stage_binary();
                let out = Command::new(runtime())
                    .args(["build", "-q", "-f", &format!("{ctx}/Dockerfile.traefik")])
                    .args(["-t", &traefik_image(), &ctx])
                    .output()
                    .expect("failed to run the image build");
                assert!(
                    out.status.success(),
                    "{} build (Traefik image) failed:\n{}",
                    runtime(),
                    String::from_utf8_lossy(&out.stderr)
                );
            })
        })
    });
}

/// A running Traefik with two sites, `test.example` over HTTP and HTTPS
/// and `api.example` over HTTP, and stop-bots told it is Traefik's.
/// Removed on drop.
struct Traefik {
    name: String,
}

/// The sites' own file, which stop-bots never writes.
const TRAEFIK_SITES: &str = "/etc/traefik/dynamic/sites.yml";

/// The file stop-bots writes.
const TRAEFIK_ROUTERS: &str = "/etc/traefik/dynamic/stop-bots.yml";

impl Traefik {
    fn start(name: &str) -> Traefik {
        build_traefik_image();
        let name = scoped(name);
        remove_container(&name);
        let out = Command::new(runtime())
            .args(["run", "-d", "--name", &name, &traefik_image()])
            .output()
            .expect("failed to start the container");
        assert!(
            out.status.success(),
            "{} run failed:\n{}",
            runtime(),
            String::from_utf8_lossy(&out.stderr)
        );
        let traefik = Traefik { name };
        traefik.sh(
            "setsid nohup whoami --port 8001 >/dev/null 2>&1 < /dev/null &\n\
             setsid nohup traefik >/var/log/traefik/traefik.log 2>&1 < /dev/null &",
        );
        traefik.wait_until_serving();
        let chosen = traefik.stop_bots("set-web-server traefik");
        assert!(chosen.contains("Traefik"), "set-web-server said:\n{chosen}");
        traefik.stop_bots("set-log-paths --access-log /var/log/traefik/access.log");
        // One site per router: `test.example` has two.
        let scanned = traefik.stop_bots("scan-sites");
        assert!(
            scanned.contains("Discovered 3 site(s)"),
            "scan-sites said:\n{scanned}"
        );
        traefik
    }

    fn run(&self, cmd: &str) -> (bool, String, String) {
        exec_in(&self.name, cmd)
    }

    fn sh(&self, cmd: &str) -> String {
        sh_in(&self.name, cmd)
    }

    fn stop_bots(&self, args: &str) -> String {
        self.sh(&format!("stop-bots {args} --db /tmp/db.sqlite3"))
    }

    /// Blocked bots, one per pattern, through the real bot-list parser:
    /// `patterns` are JSON string bodies, escapes and all.
    fn seed_bots(&self, patterns: &[&str]) {
        let accepted: Vec<String> = patterns.iter().map(|p| format!("\"{p}\"")).collect();
        let json = format!(
            r#"[{{"id":"listed","categories":["ai"],"pattern":{{"accepted":[{}],"forbidden":[]}},"url":"https://example.invalid/listed"}}]"#,
            accepted.join(",")
        );
        self.sh(&format!("cat > /tmp/bots.json <<'JSON'\n{json}\nJSON"));
        self.stop_bots("update-bot-lists --source /tmp/bots.json");
    }

    /// `apply-blocks` as an operator runs it, and then the wait for
    /// Traefik to read the file, which it does by itself and a moment
    /// later.
    fn apply(&self) -> String {
        let said = self.stop_bots("apply-blocks");
        self.wait_for_routers();
        said
    }

    fn wait_until_serving(&self) {
        for _ in 0..100 {
            if self.status("test.example", "/", "") == "200" {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let log = self.run("cat /var/log/traefik/traefik.log").1;
        panic!("Traefik never served test.example:\n{log}");
    }

    /// Every router Traefik has loaded from stop-bots' file, as `(name,
    /// status, errors)`, from its API.
    fn loaded_routers(&self) -> Vec<(String, String, String)> {
        let (_, out, _) =
            self.run("curl -s 'http://127.0.0.1:8080/api/http/routers?per_page=1000'");
        let Ok(routers) = serde_json::from_str::<Vec<serde_json::Value>>(&out) else {
            return Vec::new();
        };
        routers
            .iter()
            .filter_map(|router| {
                let name = router["name"].as_str()?;
                name.starts_with("stop-bots").then(|| {
                    (
                        name.to_string(),
                        router["status"].as_str().unwrap_or_default().to_string(),
                        router["error"].to_string(),
                    )
                })
            })
            .collect()
    }

    /// Waits until the routers Traefik has loaded are the ones the file
    /// names now, and fails unless every one of them is enabled: a router
    /// Traefik could not read is switched off, quietly, and blocks nothing.
    fn wait_for_routers(&self) {
        // The names under `routers:` only: the middleware and the service
        // are named alike, at the same depth.
        let (_, written, _) = self.run(&format!(
            "awk '/^  [a-z]/ {{ routers = ($1 == \"routers:\") }} \
             routers && /^    stop-bots[^ ]*:$/ {{ sub(\":\", \"\", $1); print $1 }}' {TRAEFIK_ROUTERS}"
        ));
        let mut written: Vec<String> = written
            .lines()
            .map(|name| format!("{}@file", name.trim()))
            .collect();
        written.sort();
        let mut loaded = Vec::new();
        for _ in 0..100 {
            loaded = self.loaded_routers();
            let mut names: Vec<String> = loaded.iter().map(|(name, ..)| name.clone()).collect();
            names.sort();
            if names == written {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let names: Vec<&str> = loaded.iter().map(|(name, ..)| name.as_str()).collect();
        assert_eq!(
            names.len(),
            written.len(),
            "Traefik loaded {loaded:?}, the file names {written:?}"
        );
        for (name, status, error) in &loaded {
            assert_eq!(status, "enabled", "Traefik could not use {name}: {error}");
        }
    }

    /// The status `host` answers `path` with over HTTP, `000` for no
    /// answer.
    fn status(&self, host: &str, path: &str, curl_args: &str) -> String {
        let (_, stdout, _) = self.run(&format!(
            "curl -s -o /dev/null -w '%{{http_code}}' -H 'Host: {host}' {curl_args} http://127.0.0.1{path}"
        ));
        stdout.trim().to_string()
    }

    /// The same over HTTPS, on Traefik's own certificate.
    fn status_tls(&self, host: &str, path: &str, curl_args: &str) -> String {
        let (_, stdout, _) = self.run(&format!(
            "curl -sk -o /dev/null -w '%{{http_code}}' --resolve {host}:443:127.0.0.1 \
             {curl_args} https://{host}{path}"
        ));
        stdout.trim().to_string()
    }
}

impl Drop for Traefik {
    fn drop(&mut self) {
        remove_container(&self.name);
    }
}

#[test]
fn traefik_turns_away_a_blocked_bot_and_serves_everyone_else() {
    if !enabled() {
        return;
    }
    let traefik = Traefik::start("sb-traefik-blocks");
    let sites = traefik.sh(&format!("cat {TRAEFIK_SITES}"));
    traefik.seed_bots(&["EvilBot"]);
    traefik.apply();

    let cases = [
        ("test.example", BAD_AGENT, "403", "a listed bot"),
        (
            "test.example",
            "-A 'evilbot'",
            "403",
            "case-insensitive, as NGINX's `~*` is",
        ),
        ("test.example", BROWSER, "200", "a browser"),
        ("api.example", BAD_AGENT, "403", "the other site"),
        ("nobody.example", BAD_AGENT, "403", "a host no file names"),
        (
            "nobody.example",
            BROWSER,
            "404",
            "nor is anything else changed there",
        ),
    ];
    for (host, agent, expected, what) in cases {
        assert_eq!(traefik.status(host, "/", agent), expected, "{what}");
    }
    assert_eq!(
        traefik.status_tls("test.example", "/", BAD_AGENT),
        "403",
        "over TLS"
    );
    assert_eq!(
        traefik.status_tls("test.example", "/", BROWSER),
        "200",
        "a browser over TLS"
    );
    assert_eq!(
        traefik.sh(&format!("cat {TRAEFIK_SITES}")),
        sites,
        "the sites' own file was written"
    );
}

/// What Traefik turns away it also logs, with the user agent, which is
/// what the detectors and the tally of who was turned away read. And a
/// probe in that log is blocked, through Traefik's own `X-Forwarded-For`
/// handling; see `Dockerfile.traefik`.
#[test]
fn traefik_access_log_is_read_by_the_detectors() {
    if !enabled() {
        return;
    }
    let traefik = Traefik::start("sb-traefik-log");
    traefik.seed_bots(&["EvilBot"]);
    traefik.apply();
    let from = |address: &str| format!("-H 'X-Forwarded-For: {address}'");
    traefik.status(
        "test.example",
        "/",
        &format!("{} {BAD_AGENT}", from("203.0.113.8")),
    );
    traefik.status(
        "test.example",
        "/",
        &format!("{} -A 'TraefikLogProbe/1.0'", from("203.0.113.9")),
    );
    traefik.status("test.example", "/.env", &from("203.0.113.10"));

    let log = traefik.sh("cat /var/log/traefik/access.log");
    assert!(
        log.lines().any(|line| line.contains("203.0.113.8")
            && line.contains(" 403 ")
            && line.contains("EvilBot")),
        "the refusal is not in the log:\n{log}"
    );
    let recorded = traefik.stop_bots("record-access-stats");
    let stats = traefik.stop_bots("list-access-stats");
    assert!(
        stats.contains("TraefikLogProbe/1.0"),
        "record-access-stats said:\n{recorded}\nlist-access-stats said:\n{stats}"
    );
    let detected = traefik.stop_bots("run-detector probe-paths");
    let rules = traefik.stop_bots("list-firewall-rules");
    assert!(
        rules.contains("203.0.113.10") && !rules.contains("203.0.113.9"),
        "run-detector probe-paths said:\n{detected}\nlist-firewall-rules said:\n{rules}"
    );
}

/// A site with settings of its own gets routers of its own, and the
/// host-wide ones leave it to them.
#[test]
fn traefik_exempts_a_path_on_one_site_only() {
    if !enabled() {
        return;
    }
    let traefik = Traefik::start("sb-traefik-exempt");
    traefik.seed_bots(&["EvilBot"]);
    traefik.stop_bots("add-exempt-path --site test.example --path /open/");
    traefik.apply();

    let cases = [
        ("test.example", "/open/x", "200", "the exempt path"),
        (
            "test.example",
            "/OPEN/x",
            "200",
            "ignoring case, as NGINX's exemption does",
        ),
        ("test.example", "/", "403", "the rest of the site"),
        (
            "api.example",
            "/open/x",
            "403",
            "the same path on the other site",
        ),
    ];
    for (host, path, expected, what) in cases {
        assert_eq!(traefik.status(host, path, BAD_AGENT), expected, "{what}");
    }
    assert_eq!(
        traefik.status_tls("test.example", "/open/x", BAD_AGENT),
        "200",
        "the exempt path over TLS"
    );
    let status = traefik.stop_bots("status");
    assert!(
        status.contains("[OK] Traefik routers are applied"),
        "status said:\n{status}"
    );
}

#[test]
fn traefik_turns_away_a_request_without_a_user_agent_where_asked() {
    if !enabled() {
        return;
    }
    let traefik = Traefik::start("sb-traefik-rules");
    traefik.stop_bots("set-site-rule --site test.example --rule no-user-agent --enabled true");
    traefik.apply();

    let without = "-H 'User-Agent:'";
    assert_eq!(traefik.status("test.example", "/", without), "403");
    assert_eq!(traefik.status("test.example", "/", BROWSER), "200");
    assert_eq!(
        traefik.status("api.example", "/", without),
        "200",
        "the other site"
    );
    // ACME's path stays open whatever the rule: whoami answers it.
    assert_eq!(
        traefik.status("test.example", "/.well-known/acme-challenge/x", without),
        "200"
    );
}

/// Patterns with what YAML, Traefik's rule parser or Go's regular
/// expressions read differently from PCRE: each loads, and each turns away
/// exactly the client it names. One router Traefik could not read would
/// turn away nobody. (A bare `"` never gets this far: the fetch leaves it
/// out for every server.)
#[test]
fn traefik_reads_every_character_a_pattern_carries() {
    if !enabled() {
        return;
    }
    let traefik = Traefik::start("sb-traefik-hostile");
    traefik.seed_bots(&[
        "It's\\\\ a\\\\ Bot",
        "Back`tick",
        "caf\\\\é",
        "Dollar\\\\$Bot",
        "Brace\\\\{Bot",
        "Repeat{2}Bot",
    ]);
    traefik.apply();
    let cases = [
        ("It's a Bot/1", "403"),
        ("Back`tick/1", "403"),
        ("CAFÉ/1", "403"),
        ("Dollar$Bot/1", "403"),
        ("Brace{Bot/1", "403"),
        ("RepeattBot/1", "403"),
        ("RepeatBot/1", "200"),
        ("Mozilla/5.0 Firefox/130.0", "200"),
    ];
    for (agent, expected) in cases {
        assert_eq!(
            traefik.status("test.example", "/", &format!("-A {}", sh_quoted(agent))),
            expected,
            "{agent}"
        );
    }
}

/// The same under a real Traefik, through Go's regular expressions.
#[test]
fn traefik_turns_away_old_browsers_once_the_list_is_on() {
    if !enabled() {
        return;
    }
    let traefik = Traefik::start("sb-traefik-old-browsers");
    traefik.stop_bots("set-old-browsers --enabled true");
    traefik.apply();

    for (user_agent, expected, what) in OLD_AND_NEW {
        assert_eq!(
            traefik.status(
                "test.example",
                "/",
                &format!("-A {}", sh_quoted(user_agent))
            ),
            expected,
            "{what}"
        );
    }
}

#[test]
fn traefik_uninstall_takes_the_routers_away() {
    if !enabled() {
        return;
    }
    let traefik = Traefik::start("sb-traefik-uninstall");
    traefik.seed_bots(&["EvilBot"]);
    traefik.apply();
    assert_eq!(traefik.status("test.example", "/", BAD_AGENT), "403");

    let said = traefik.stop_bots("uninstall web-server");

    traefik.sh(&format!("test ! -e {TRAEFIK_ROUTERS}"));
    for _ in 0..100 {
        if traefik.loaded_routers().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(
        traefik.status("test.example", "/", BAD_AGENT),
        "200",
        "uninstall said:\n{said}"
    );
}

// ---- NPMplus ----
//
// The real NPMplus image, run as its compose file runs it, with its data
// directory a bind mount of a directory on the host. stop-bots runs where
// an operator runs it: on the host, outside the container, writing into
// that directory and testing and reloading NPMplus's NGINX with
// `<runtime> exec`. The hosts are created through NPMplus's own API, so
// the config stop-bots reads is the config NPMplus renders.
//
// Nothing here builds an image. NPMplus's is Alpine's, on musl, which the
// binary under test would not run in, and running it outside is the point.

/// The NPMplus release these tests run, pinned: a new one can change what
/// it renders, and that should be a change to this line, not a red build
/// nobody asked for.
const NPMPLUS_IMAGE: &str = "docker.io/zoeyvid/npmplus:2026-10-22-r1";

/// The admin NPMplus creates on its first start, which the API is driven
/// as.
const NPMPLUS_ADMIN: &str = r#"{"identity":"admin@example.com","secret":"stop-bots-test"}"#;

/// A running NPMplus with two proxy hosts, `a.example` and `b.example`,
/// both handing requests to a server answering 200 on `127.0.0.1:8001`,
/// and stop-bots told it is NPMplus's. Removed on drop.
struct Npmplus {
    name: String,
    /// Holds NPMplus's data directory, `data/`, and stop-bots' own host
    /// settings and database, where an uninstall under `--prefix` of it
    /// reads them.
    dir: tempfile::TempDir,
}

impl Npmplus {
    fn start(name: &str) -> Npmplus {
        use std::os::unix::fs::MetadataExt;
        let name = scoped(name);
        remove_container(&name);
        let dir = tempfile::tempdir().expect("failed to make a data directory");
        let data = dir.path().join("data");
        // NPMplus registers an ACME account on its first start, and waits
        // for ever if it cannot. A file under the account directory is
        // what it checks, and with one there it never asks: these tests
        // must not register an account with Let's Encrypt on every run,
        // or reach the network at all.
        let account = data.join("tls/certbot/accounts/acme-v02.api.letsencrypt.org/directory/test");
        std::fs::create_dir_all(&account).unwrap();
        std::fs::write(account.join("regr.json"), "{}").unwrap();
        // With no network, Podman leaves no `resolv.conf` in the
        // container, and NPMplus's NGINX will not start without one.
        let resolv = dir.path().join("resolv.conf");
        std::fs::write(&resolv, "nameserver 127.0.0.1\n").unwrap();

        let mut run = Command::new(runtime());
        run.args(["run", "-d", "--name", &name, "--network", "none"])
            .arg("-v")
            .arg(format!("{}:/etc/resolv.conf:ro", resolv.display()))
            .arg("-v")
            .arg(format!("{}:/data", data.display()))
            .args([
                "-e",
                "TZ=UTC",
                "-e",
                "LOGROTATE=true",
                "-e",
                "DISABLE_IPV6=true",
            ])
            .args(["-e", "INITIAL_ADMIN_EMAIL=admin@example.com"])
            .args(["-e", "INITIAL_ADMIN_PASSWORD=stop-bots-test"]);
        // Rootless Podman's root in the container is this user outside it,
        // so what NPMplus writes is this user's already. Docker's is the
        // daemon's root: told to run as this user instead, NPMplus writes
        // files that stop-bots, running as this user, can write too.
        if !runtime_is_podman() {
            let owner = std::fs::metadata(dir.path()).unwrap();
            run.args(["-e", &format!("PUID={}", owner.uid())])
                .args(["-e", &format!("PGID={}", owner.gid())]);
        }
        let out = run
            .arg(NPMPLUS_IMAGE)
            .output()
            .expect("failed to start the container");
        assert!(
            out.status.success(),
            "{} run failed:\n{}",
            runtime(),
            String::from_utf8_lossy(&out.stderr)
        );
        let npmplus = Npmplus { name, dir };
        npmplus.wait_until_serving();
        let backend = Command::new(runtime())
            .args(["exec", "-d", &npmplus.name])
            .args([
                "python3",
                "-m",
                "http.server",
                "8001",
                "--bind",
                "127.0.0.1",
            ])
            .args(["--directory", "/tmp"])
            .output()
            .expect("failed to start the backend");
        assert!(backend.status.success(), "the backend did not start");
        npmplus.api("POST", "/api/tokens", NPMPLUS_ADMIN);
        for host in ["a.example", "b.example"] {
            npmplus.api(
                "POST",
                "/api/nginx/proxy-hosts",
                &format!(
                    r#"{{"domain_names":["{host}"],"forward_scheme":"http","forward_host":"127.0.0.1","forward_port":8001,"locations":[],"meta":{{}}}}"#
                ),
            );
        }
        npmplus.wait_for_status("b.example", "/", BROWSER, "200");

        let exec = |command: &str| format!("{} exec {} {command}", runtime(), npmplus.name);
        let chosen = npmplus.stop_bots(&[
            "set-web-server",
            "npmplus",
            "--root",
            data.to_str().unwrap(),
            "--test",
            &exec("nginx -t"),
            "--reload",
            &exec("nginx -s reload"),
        ]);
        assert!(chosen.contains("NPMplus"), "set-web-server said:\n{chosen}");
        let scanned = npmplus.stop_bots(&["scan-sites"]);
        assert!(
            scanned.contains("Discovered 2 site(s)"),
            "scan-sites said:\n{scanned}"
        );
        npmplus
    }

    /// NPMplus's data directory, as the host sees it.
    fn data(&self) -> std::path::PathBuf {
        self.dir.path().join("data")
    }

    fn run(&self, cmd: &str) -> (bool, String, String) {
        exec_in(&self.name, cmd)
    }

    fn sh(&self, cmd: &str) -> String {
        sh_in(&self.name, cmd)
    }

    /// The binary under test, on the host, with this NPMplus's host
    /// settings and database. Asserts it succeeded.
    fn stop_bots(&self, args: &[&str]) -> String {
        let out = Command::new(env!("CARGO_BIN_EXE_stop-bots"))
            .env(
                "STOP_BOTS_HOST_CONF",
                self.dir.path().join("etc/stop-bots/host.conf"),
            )
            .args(args)
            .arg("--db")
            .arg(self.dir.path().join("db.sqlite3"))
            .output()
            .expect("failed to run stop-bots");
        let (stdout, stderr) = (
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        assert!(
            out.status.success(),
            "stop-bots {args:?} failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        format!("{stdout}{stderr}")
    }

    /// A blocked bot, through the real bot-list parser.
    fn seed_bot(&self, pattern: &str) {
        let list = self.dir.path().join("bots.json");
        std::fs::write(
            &list,
            format!(
                r#"[{{"id":"listed","categories":["ai"],"pattern":{{"accepted":["{pattern}"],"forbidden":[]}},"url":"https://example.invalid/listed"}}]"#
            ),
        )
        .unwrap();
        self.stop_bots(&["update-bot-lists", "--source", list.to_str().unwrap()]);
    }

    /// `apply-blocks` as an operator runs it, and then the wait for the
    /// reload: NGINX's old workers answer for a moment after it.
    fn apply(&self) -> String {
        let said = self.stop_bots(&["apply-blocks"]);
        self.wait_for_status("a.example", "/", BAD_AGENT, "403");
        said
    }

    /// One call to NPMplus's API, signed in by the cookie `/api/tokens`
    /// sets, asserting it succeeded.
    fn api(&self, method: &str, path: &str, body: &str) -> String {
        let (_, out, err) = self.run(&format!(
            "curl -sk -b /tmp/jar -c /tmp/jar -X {method} -H 'Content-Type: application/json' \
             -w '\\n%{{http_code}}' -d '{body}' https://127.0.0.1:81{path}"
        ));
        let (answer, status) = out.rsplit_once('\n').unwrap_or((&out, ""));
        assert!(
            status.starts_with('2'),
            "NPMplus answered {method} {path} with {status}:\n{answer}{err}"
        );
        answer.to_string()
    }

    fn wait_until_serving(&self) {
        for _ in 0..300 {
            let (_, status, _) =
                self.run("curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:81/api/");
            if status == "200" {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let log = Command::new(runtime())
            .args(["logs", &self.name])
            .output()
            .map(|out| String::from_utf8_lossy(&out.stderr).to_string())
            .unwrap_or_default();
        panic!("NPMplus never started:\n{log}");
    }

    /// The status `host` answers `path` with, `000` for no answer.
    fn status(&self, host: &str, path: &str, curl_args: &str) -> String {
        let (_, stdout, _) = self.run(&format!(
            "curl -s -o /dev/null -w '%{{http_code}}' -H 'Host: {host}' {curl_args} http://127.0.0.1{path}"
        ));
        stdout.trim().to_string()
    }

    /// [`Self::status`], polled until it is `want` or ten seconds have
    /// passed, and asserted.
    fn wait_for_status(&self, host: &str, path: &str, curl_args: &str, want: &str) {
        let mut got = String::new();
        for _ in 0..100 {
            got = self.status(host, path, curl_args);
            if got == want {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("{host}{path} with {curl_args} answered {got}, not {want}");
    }
}

impl Drop for Npmplus {
    fn drop(&mut self) {
        remove_container(&self.name);
    }
}

#[test]
fn npmplus_turns_away_a_blocked_bot_on_every_host() {
    if !enabled() {
        return;
    }
    let npmplus = Npmplus::start("sb-npmplus-blocks");
    let rendered = std::fs::read_to_string(npmplus.data().join("nginx/proxy_host/1.conf")).unwrap();
    npmplus.seed_bot("EvilBot");
    npmplus.apply();

    let cases = [
        ("a.example", BAD_AGENT, "403", "a listed bot"),
        (
            "a.example",
            "-A 'evilbot'",
            "403",
            "case-insensitive, as NGINX's `~*` is",
        ),
        ("a.example", BROWSER, "200", "a browser"),
        ("b.example", BAD_AGENT, "403", "the other host"),
        ("b.example", BROWSER, "200", "a browser on the other host"),
    ];
    for (host, agent, expected, what) in cases {
        assert_eq!(npmplus.status(host, "/", agent), expected, "{what}");
    }
    assert_eq!(
        std::fs::read_to_string(npmplus.data().join("nginx/proxy_host/1.conf")).unwrap(),
        rendered,
        "the host NPMplus rendered was written"
    );
}

/// NPMplus renders a host's file again whenever the host is saved. The
/// rule is not in that file, so it is still there afterwards.
#[test]
fn npmplus_keeps_the_rule_when_it_renders_a_host_again() {
    if !enabled() {
        return;
    }
    let npmplus = Npmplus::start("sb-npmplus-resave");
    npmplus.seed_bot("EvilBot");
    npmplus.apply();
    let host = npmplus.data().join("nginx/proxy_host/1.conf");
    let before = std::fs::read_to_string(&host).unwrap();

    npmplus.api(
        "PUT",
        "/api/nginx/proxy-hosts/1",
        r#"{"domain_names":["a.example","www.a.example"]}"#,
    );

    assert_ne!(
        std::fs::read_to_string(&host).unwrap(),
        before,
        "NPMplus did not render the host again"
    );
    npmplus.wait_for_status("a.example", "/", BROWSER, "200");
    assert_eq!(npmplus.status("a.example", "/", BAD_AGENT), "403");
}

/// The files in `custom_nginx` survive NPMplus's own start, which creates
/// them when they are missing and must leave them alone when they are not.
#[test]
fn npmplus_keeps_the_rule_across_a_restart() {
    if !enabled() {
        return;
    }
    let npmplus = Npmplus::start("sb-npmplus-restart");
    npmplus.seed_bot("EvilBot");
    npmplus.apply();

    let out = Command::new(runtime())
        .args(["restart", &npmplus.name])
        .output()
        .expect("failed to restart the container");
    assert!(out.status.success(), "the restart failed");
    npmplus.wait_until_serving();

    assert_eq!(npmplus.status("a.example", "/", BAD_AGENT), "403");
}

/// The `http`-level half, `custom_nginx/stop-bots/`, as the container reads
/// it: the generated robots.txt, served to the bot it turns away, and the
/// rate-limit zone.
#[test]
fn npmplus_serves_robots_txt_and_rate_limits() {
    if !enabled() {
        return;
    }
    let npmplus = Npmplus::start("sb-npmplus-robots");
    npmplus.seed_bot("EvilBot");
    npmplus.stop_bots(&["set-robots-txt", "--enabled", "true"]);
    npmplus.stop_bots(&["set-rate-limit", "--enabled", "true"]);
    npmplus.apply();

    let robots = npmplus.sh(&format!(
        "curl -s -H 'Host: a.example' {BAD_AGENT} http://127.0.0.1/robots.txt"
    ));
    assert!(
        robots.starts_with("# Generated by stop-bots"),
        "robots.txt was:\n{robots}"
    );
    let statuses = npmplus.sh("for i in $(seq 1 60); do \
         curl -s -o /dev/null -w '%{http_code}\\n' -H 'Host: a.example' http://127.0.0.1/; done");
    assert!(
        statuses.lines().any(|status| status == "429"),
        "60 requests at once were never limited:\n{statuses}"
    );
}

/// A trusted client is let through whatever it is called: the trust file
/// is in `custom_nginx/stop-bots/` and the block reads its variable, so
/// this fails unless NPMplus's `http` block includes it.
#[test]
fn npmplus_lets_a_trusted_client_through() {
    if !enabled() {
        return;
    }
    let npmplus = Npmplus::start("sb-npmplus-trust");
    npmplus.seed_bot("EvilBot");
    npmplus.stop_bots(&["add-trusted", "--address", "203.0.113.7"]);
    npmplus.apply();

    // NPMplus takes the client from `X-Forwarded-For` when the request
    // comes from loopback, as it does for a proxy in front of it.
    let from = |address: &str| format!("-H 'X-Forwarded-For: {address}' {BAD_AGENT}");
    let cases = [
        ("203.0.113.7", "200", "the trusted address"),
        ("203.0.113.8", "403", "any other"),
    ];
    for (address, expected, what) in cases {
        assert_eq!(
            npmplus.status("a.example", "/", &from(address)),
            expected,
            "{what}"
        );
    }
}

/// What NPMplus logs, in its own format, is what the detectors read: a
/// probe in it is blocked.
#[test]
fn npmplus_access_log_is_read_by_the_detectors() {
    if !enabled() {
        return;
    }
    let npmplus = Npmplus::start("sb-npmplus-log");
    let log = npmplus.data().join("nginx/logs/access.log");
    npmplus.stop_bots(&["set-log-paths", "--access-log", log.to_str().unwrap()]);
    let from = |address: &str| format!("-H 'X-Forwarded-For: {address}'");
    npmplus.status(
        "a.example",
        "/",
        &format!("{} -A 'NpmplusLogProbe/1.0'", from("203.0.113.9")),
    );
    npmplus.status("a.example", "/.env", &from("203.0.113.10"));

    let recorded = npmplus.stop_bots(&["record-access-stats"]);
    let stats = npmplus.stop_bots(&["list-access-stats"]);
    assert!(
        stats.contains("NpmplusLogProbe/1.0"),
        "record-access-stats said:\n{recorded}\nlist-access-stats said:\n{stats}"
    );
    let detected = npmplus.stop_bots(&["run-detector", "probe-paths"]);
    let rules = npmplus.stop_bots(&["list-firewall-rules"]);
    assert!(
        rules.contains("203.0.113.10") && !rules.contains("203.0.113.9"),
        "run-detector probe-paths said:\n{detected}\nlist-firewall-rules said:\n{rules}"
    );
}

/// `uninstall web-server` leaves NPMplus's two files as NPMplus made them,
/// and an NGINX that still loads and serves. Under `--prefix`, since an
/// uninstall on the host itself needs root: that runs no system program,
/// so the test and the reload are this test's.
#[test]
fn npmplus_uninstall_puts_its_files_back() {
    if !enabled() {
        return;
    }
    let npmplus = Npmplus::start("sb-npmplus-uninstall");
    let custom = npmplus.data().join("custom_nginx");
    let read = |name: &str| std::fs::read_to_string(custom.join(name)).unwrap();
    let before = (read("server_http.conf"), read("http_top.conf"));
    npmplus.seed_bot("EvilBot");
    npmplus.stop_bots(&["set-robots-txt", "--enabled", "true"]);
    npmplus.apply();

    let said = npmplus.stop_bots(&[
        "uninstall",
        "web-server",
        "--prefix",
        npmplus.dir.path().to_str().unwrap(),
        "--root",
        npmplus.data().to_str().unwrap(),
    ]);

    assert_eq!(
        (read("server_http.conf"), read("http_top.conf")),
        before,
        "uninstall said:\n{said}"
    );
    assert!(
        !custom.join("stop-bots").exists(),
        "its own directory is still there:\n{said}"
    );
    npmplus.sh("nginx -t && nginx -s reload");
    npmplus.wait_for_status("a.example", "/", BAD_AGENT, "200");
}
