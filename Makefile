test:
	cargo test

build: test
	cargo build --release

deploy: build
	scp ./target/release/stop-bots www:
