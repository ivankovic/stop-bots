# Every target here is a name, not a file. Without this a directory named
# `build` or `test` — both plausible — would make `make test` say
# "up to date" and run nothing.
.PHONY: help unit-test integration-test stranger-test test hooks screenshots build deploy

# `cargo nextest run` where it is installed, plain `cargo test` otherwise.
# They run the same tests; nextest additionally enforces the per-test
# budgets in .config/nextest.toml and is what CI runs, so having it means
# a green run here means the same thing as a green run there.
RUNNER := $(shell command -v cargo-nextest >/dev/null 2>&1 && echo 'cargo nextest run' || echo 'cargo test')

# Rootless Podman for `make integration-test`, not Docker.
#
# The two are interchangeable here -- tests/container.rs drives whichever
# it is handed -- so this is a choice about the daemon, not the tests.
# Docker's runs as root and its socket has no notion of per-container
# permission, so the `docker` group is all-or-nothing: on a machine that
# also hosts root-owned containers, granting it to run this suite grants
# every one of those containers too. Podman has no daemon and keeps
# per-user storage, so the suite needs no such grant.
#
# `?=`, so the environment still wins: `STOP_BOTS_CONTAINER_RUNTIME=docker
# make integration-test` is how you check the runtime CI uses. CI itself
# calls cargo directly and never reads this file; the default there comes
# from `runtime()` in tests/container.rs, which is still `docker`.
STOP_BOTS_CONTAINER_RUNTIME ?= podman

help:
	@echo 'unit-test         everything that needs only a compiler (~20s)'
	@echo 'integration-test  the container suite: needs a runtime + NET_ADMIN (~1min)'
	@echo 'stranger-test     the README quick start on fresh Debian 12 and Ubuntu 24.04, from the .deb'
	@echo 'test              both, unit first'
	@echo 'hooks             install the pre-commit hook (fmt + clippy)'
	@echo 'screenshots       regenerate docs/screenshots/ from seeded fiction'
	@echo 'build             release binary, after unit-test'
	@echo 'deploy            build, then install it on $$DEPLOY_HOST and restart the service'
	@echo
	@echo 'test runner:       $(RUNNER)'
	@echo 'container runtime: $(STOP_BOTS_CONTAINER_RUNTIME)'

# The library's own test modules plus the end-to-end binaries in tests/.
# Needs nothing but a compiler: no Docker, no network, no root. This is
# the suite that has to stay runnable on any machine, which is why the
# container tests are a separate target rather than a slower default.
unit-test:
	$(RUNNER)

# The only place the generated NGINX and nftables output meets the real
# parsers, and the only place a firewall rule is checked by sending
# packets at it. Off by default because it needs a container runtime and
# NET_ADMIN, which the unit suite must never require.
#
# Plain `cargo test` rather than $(RUNNER): these are long by design, and
# `--nocapture` streaming their progress is the difference between
# watching a container build and staring at nothing for twenty seconds.
integration-test:
	STOP_BOTS_CONTAINER_TESTS=1 \
	STOP_BOTS_CONTAINER_RUNTIME=$(STOP_BOTS_CONTAINER_RUNTIME) \
	cargo test --test container -- --nocapture

# The stranger test: the README's quick start, from `apt install` of the
# package to `uninstall all`, on a fresh Debian 12 and a fresh Ubuntu 24.04
# (see `a_stranger_follows_the_quick_start` in tests/container.rs).
#
# It installs a .deb built the way the release builds one, static against
# musl, because the host's glibc build does not start on Debian 12. So it
# needs what CI's `deb` job needs: the x86_64-unknown-linux-musl target,
# `musl-gcc` (Debian's musl-tools) and cargo-deb. Point
# CC_x86_64_unknown_linux_musl at another musl compiler if yours is
# elsewhere. `STOP_BOTS_STRANGER_FETCH=1` runs `batch --apply` with real
# downloads, as the quick start writes it; by default it is `--no-fetch`.
CC_x86_64_unknown_linux_musl ?= musl-gcc
export CC_x86_64_unknown_linux_musl
STRANGER_DIR := target/stranger

stranger-test:
	cargo build --release --target x86_64-unknown-linux-musl
	target/x86_64-unknown-linux-musl/release/stop-bots generate-docs --out target/assets
	rm -rf $(STRANGER_DIR)
	cargo deb --no-build --no-strip --deb-version "$$(scripts/deb-version.sh)" --target x86_64-unknown-linux-musl --output $(STRANGER_DIR)/
	STOP_BOTS_CONTAINER_TESTS=1 \
	STOP_BOTS_CONTAINER_RUNTIME=$(STOP_BOTS_CONTAINER_RUNTIME) \
	STOP_BOTS_STRANGER_DEB="$$(ls $(STRANGER_DIR)/stop-bots_*.deb)" \
	cargo test --test container stranger -- --nocapture

# Unit first: it is the one that fails for a plain mistake, and there is
# no sense building containers to find out the code doesn't compile.
test: unit-test integration-test

# Opt-in, because a hook that installs itself is a hook that surprises
# someone. See .githooks/pre-commit for what it does.
hooks:
	git config core.hooksPath .githooks
	@echo 'pre-commit hook enabled. Skip it once with `git commit --no-verify`,'
	@echo 'turn it off with `git config --unset core.hooksPath`.'

# Regenerates docs/screenshots/. Seeded fiction, never the host's own logs
# — see the module comment in examples/screenshots.rs. Run it after any
# change to a screen's layout, and commit the diff.
screenshots:
	cargo run --example screenshots

build: unit-test
	cargo build --release

# Where the deployed binary has to land, and why it is not the login
# directory.
#
# `install web` writes a unit whose ExecStart names an absolute path, and
# that unit sets ProtectHome=yes — so a binary under /root or /home is
# invisible to the service even when it is plainly there. scp'ing to the
# login directory therefore deploys a file nothing runs, silently: the
# console keeps serving, from the previous binary, and the only symptom is
# that the change you just shipped is not in it.
DEPLOY_HOST ?= www
DEPLOY_PATH ?= /usr/local/bin/stop-bots
DEPLOY_UNIT ?= stop-bots-web.service

# The remote half lives in scripts/deploy-remote.sh, piped over ssh rather
# than inlined here: it is branching shell that decides whether the host
# keeps serving the old build, and `tests/container.rs` runs that exact
# file against a real systemd. See the script for what it does and why.
deploy: build
	scp ./target/release/stop-bots '$(DEPLOY_HOST):$(DEPLOY_PATH).new'
	ssh '$(DEPLOY_HOST)' 'sh -s' '$(DEPLOY_PATH)' '$(DEPLOY_UNIT)' \
		< scripts/deploy-remote.sh
