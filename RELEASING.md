# Releasing

Two publications happen per release, and they are deliberately not the same step:

| Target   | Trigger                    | Reversible?                                     |
| -------- | -------------------------- | ----------------------------------------------- |
| GitHub   | pushing a `v*` tag         | yes — delete the tag and the release, re-push    |
| crates.io| running `cargo publish`    | **no** — a version can be yanked, never replaced |

That asymmetry is why the tag-triggered workflow builds the GitHub release but does *not*
run `cargo publish`. Yanking a bad version does not free its number, so `0.0.2` would have
to be burned to fix a mistake in `0.0.1`. The publish stays a manual step with a human
watching the dry run.

## First-time setup

Publishing to crates.io needs an account and a token, once:

```
cargo login          # paste a token from https://crates.io/settings/tokens
```

No repository secrets are needed — nothing in CI talks to crates.io.

## Releasing

For the very first release the version and changelog are already in place, so start at
step 3.

1. **Bump the version** in `Cargo.toml`, and run any cargo command so `Cargo.lock` picks up
   the new version too:

   ```
   cargo check
   ```

2. **Move the `Unreleased` section** of `CHANGELOG.md` under the new version heading, add
   the date, and update the link definitions at the bottom.

3. **Check it locally.** This is the same set CI runs, and it is faster to find out here:

   ```
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test
   cargo publish --dry-run
   ```

   `--dry-run` matters: it builds the crate *from the packaged tarball*, which is the only
   way to catch a file that is present locally but excluded from the package.

   If the pty-driven tests in `tests/tui.rs` time out on a heavily loaded machine, raise
   the ceiling rather than serialising the suite: `STOP_BOTS_TEST_TIMEOUT_MS=60000 cargo
   test`.

4. **Push the branch first, and let CI finish.**

   ```
   git commit -am "release: v0.0.1"
   git push origin main
   ```

   Deliberately not in the same breath as the tag. The tag is what triggers the release
   build, and there is no point discovering a formatting failure or a bad category slug
   *after* a release has started — especially the first time, when neither workflow has
   ever executed.

5. **Tag and push the tag**, once CI is green. The tag must match the manifest version;
   the release workflow checks this and refuses to build otherwise.

   ```
   git tag -a v0.0.1 -m "v0.0.1"
   git push origin v0.0.1
   ```

   This builds the `x86_64` Linux binary and creates the GitHub release with a tarball and
   its SHA-256. Releases with a `v0.0.` prefix are marked pre-release automatically.

6. **Watch the release build finish**, then publish the crate:

   ```
   cargo publish
   ```

If something is wrong before step 6, delete the tag and the release, fix it, and start
again:

```
git push --delete origin v0.0.1
git tag -d v0.0.1
```

After step 6 the version is spent — `cargo yank` hides it from new dependants but does not
free the number.

## A note on `Cargo.lock`

It is tracked, and the release build passes `--locked` while CI does not. That is the
right way round — CI catches a dependency that has drifted, the release build is
reproducible — but it does mean a green CI is not proof that the release build will
resolve the same tree. In practice this only bites if a dependency is yanked between the
two.

## Versioning

While the crate is `0.0.x`, cargo treats every release as breaking, which is the honest
signal: `src/lib.rs` exposes every module, so the public API is currently "whatever the
binary needed". Narrowing that surface is a prerequisite for `0.1.0`, and designing it
deliberately is a prerequisite for `1.0.0`.

The MSRV in `Cargo.toml` (`rust-version`) is enforced by a dedicated CI job. Raising it is
a breaking change; a dependency raising *its* MSRV shows up as that job going red.
