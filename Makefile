test:
	cargo test

# The container suite needs Docker and NET_ADMIN, and takes ~20s. It is
# the only place the generated NGINX and nftables output meets the real
# parsers, so run it before a release even though `test` doesn't.
test-containers:
	STOP_BOTS_CONTAINER_TESTS=1 cargo test --test container -- --nocapture

# Regenerates docs/screenshots/. Seeded fiction, never the host's own logs
# — see the module comment in examples/screenshots.rs. Run it after any
# change to a screen's layout, and commit the diff.
screenshots:
	cargo run --example screenshots

build: test
	cargo build --release

deploy: build
	scp ./target/release/stop-bots www:
