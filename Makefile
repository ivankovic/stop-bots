# Every target here is a name, not a file. Without this a directory named
# `build` or `test` — both plausible — would make `make test` say
# "up to date" and run nothing.
.PHONY: help unit-test integration-test test hooks screenshots build deploy

# `cargo nextest run` where it is installed, plain `cargo test` otherwise.
# They run the same tests; nextest additionally enforces the per-test
# budgets in .config/nextest.toml and is what CI runs, so having it means
# a green run here means the same thing as a green run there.
RUNNER := $(shell command -v cargo-nextest >/dev/null 2>&1 && echo 'cargo nextest run' || echo 'cargo test')

help:
	@echo 'unit-test         everything that needs only a compiler (~20s)'
	@echo 'integration-test  the container suite: needs Docker and NET_ADMIN (~1min)'
	@echo 'test              both, unit first'
	@echo 'hooks             install the pre-commit hook (fmt + clippy)'
	@echo 'screenshots       regenerate docs/screenshots/ from seeded fiction'
	@echo 'build             release binary, after unit-test'
	@echo 'deploy            build, then install it on $$DEPLOY_HOST and restart the service'
	@echo
	@echo 'test runner: $(RUNNER)'

# The library's own test modules plus the end-to-end binaries in tests/.
# Needs nothing but a compiler: no Docker, no network, no root. This is
# the suite that has to stay runnable on any machine, which is why the
# container tests are a separate target rather than a slower default.
unit-test:
	$(RUNNER)

# The only place the generated NGINX and nftables output meets the real
# parsers, and the only place a firewall rule is checked by sending
# packets at it. Off by default because it needs Docker and NET_ADMIN,
# which the unit suite must never require.
#
# Plain `cargo test` rather than $(RUNNER): these are long by design, and
# `--nocapture` streaming their progress is the difference between
# watching a container build and staring at nothing for twenty seconds.
integration-test:
	STOP_BOTS_CONTAINER_TESTS=1 cargo test --test container -- --nocapture

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

# Staged next to the target and moved into place rather than written over
# it: replacing a running executable in place fails with ETXTBSY, and a
# rename swaps the directory entry while the running process keeps the old
# inode until it restarts.
#
# `try-restart` rather than `restart` so this is still correct on a host
# where the console is run by hand instead of by systemd — it restarts the
# unit if it is running and does nothing if it is not. Guarded by
# `systemctl cat` so a host with no unit at all says so instead of failing.
#
# It prints the unit's ExecStart and the deployed file's timestamp, because
# `--version` cannot tell two builds of the same 0.0.x apart: the way this
# fails is that everything succeeds and the console keeps serving the old
# code, and the only two facts that distinguish that are *where* the unit
# looks and *when* the file landed.
deploy: build
	scp ./target/release/stop-bots '$(DEPLOY_HOST):$(DEPLOY_PATH).new'
	ssh '$(DEPLOY_HOST)' 'set -e; \
		chmod 755 $(DEPLOY_PATH).new; \
		mv $(DEPLOY_PATH).new $(DEPLOY_PATH); \
		if systemctl cat $(DEPLOY_UNIT) >/dev/null 2>&1; then \
			systemctl try-restart $(DEPLOY_UNIT); \
			printf "unit runs: "; \
			systemctl show $(DEPLOY_UNIT) -p ExecStart --value | \
				sed -n "s/.*argv\\[\\]=\\([^ ]*\\).*/\\1/p"; \
		else \
			echo "no $(DEPLOY_UNIT) on this host — nothing restarted"; \
		fi; \
		printf "deployed:  "; ls -l --time-style=+%Y-%m-%dT%H:%M:%SZ $(DEPLOY_PATH) | \
			awk "{print \$$6, \$$7}"'
