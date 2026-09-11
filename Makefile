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

deploy: build
	scp ./target/release/stop-bots www:
