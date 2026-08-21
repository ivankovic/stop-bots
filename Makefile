test:
	cargo test

# The container suite needs Docker and NET_ADMIN, and takes ~20s. It is
# the only place the generated NGINX and nftables output meets the real
# parsers, so run it before a release even though `test` doesn't.
container-test:
	STOP_BOTS_CONTAINER_TESTS=1 cargo test --test container -- --nocapture

build: test
	cargo build --release

deploy: build
	scp ./target/release/stop-bots www:
