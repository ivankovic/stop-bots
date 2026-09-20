# Releasing

Two publications happen per release, and they are deliberately not the same step:

| Target   | Trigger                    | Reversible?                                     |
| -------- | -------------------------- | ----------------------------------------------- |
| GitHub   | pushing a `v*` tag         | yes — delete the tag and the release, re-push    |
| APT      | the same tag               | yes — revert the `gh-pages` commit               |
| crates.io| running `cargo publish`    | **no** — a version can be yanked, never replaced |

The APT repository rides along with the GitHub release: the same workflow builds the
`.deb`s and publishes them, so there is no third step to remember. It is listed
separately only because it can fail on its own, and what to do about that is at the
bottom of this file.

That asymmetry is why the tag-triggered workflow builds the GitHub release but does *not*
run `cargo publish`. Yanking a bad version does not free its number, so `0.0.2` would have
to be burned to fix a mistake in `0.0.1`. The publish stays a manual step with a human
watching the dry run.

## First-time setup

### crates.io

An account and a token, once:

```
cargo login          # paste a token from https://crates.io/settings/tokens
```

No repository secrets are needed — nothing in CI talks to crates.io.

### The APT repository

Three things, all once, and none of them per-release.

**1. A signing key.** It signs the repository index, and it is what users pin with
`signed-by`, so replacing it later means every existing installation stops updating
until its owner re-adds the new one. Generate it to last:

```sh
gpg --batch --pinentry-mode loopback --passphrase '' \
    --quick-gen-key 'stop-bots apt repository <marko@ivankovic.me>' rsa4096 sign never
```

`never`, deliberately: an expiring key means `apt update` starts failing on every
machine on a date nobody wrote down. Revocation is the mechanism for a compromised
key, not expiry.

`--pinentry-mode loopback --passphrase ''` is load-bearing rather than shorthand:
`--batch` alone makes gpg reach for a pinentry it has no terminal for and fail with
`Inappropriate ioctl for device`. Drop all three to be prompted for a passphrase
instead and store it as `APT_GPG_PASSPHRASE` — `build-apt-repo.sh` signs without one
when that is unset. Be clear about what the passphrase buys, though: it would sit in
the same secret store as the key it protects, so it defends only against the key
leaking on its own.

The key in use is `5760551466101E868D04F50235F63282482780A7`, generated 2026-09-20.

**2. The repository secret.** Pipe it rather than pasting it, so the private key never
lands in a terminal, a clipboard or a shell history:

```sh
gpg --armor --export-secret-keys '<fingerprint>' \
  | gh secret set APT_GPG_PRIVATE_KEY --repo ivankovic/stop-bots
```

| Secret | Value |
| --- | --- |
| `APT_GPG_PRIVATE_KEY` | the armoured private key |
| `APT_GPG_PASSPHRASE` | its passphrase — leave unset if the key has none, as this one does |

A repository secret is enough; the `apt` job has no environment attached, and an
environment secret would need one added first.

**Back the private key up somewhere you control.** It exists in the secret store and
nowhere else otherwise. Losing it does not break installed clients immediately, but
every future release would be signed with a new key — and every user who added the old
one gets a signature failure on their next `apt update` until they re-fetch it. That is
also what makes rotation expensive, so rotate on evidence, not on a schedule. Keep the
revocation certificate from `~/.gnupg/openpgp-revocs.d/` with it; it is the only thing
that lets you retire the key if it leaks.

**3. GitHub Pages**, under Settings → Pages: source *Deploy from a branch*, branch
`gh-pages`, folder `/`.

***Deploy from a branch* is not the default, and the default fails silently.** Enabling
Pages gives you *GitHub Actions* as the source, which publishes only what a workflow
uploads through `actions/deploy-pages`. The `apt` job pushes a branch instead, so under
that setting it pushes successfully, reports success, and serves nothing. Check which
one is set rather than assuming:

```sh
gh api repos/ivankovic/stop-bots/pages --jq '{build_type, source}'
# want {"build_type":"legacy","source":{"branch":"gh-pages","path":"/"}}
# "workflow" means the branch is being ignored
```

`legacy` is the API's name for branch-based deployment, and it can be set directly:

```sh
gh api -X PUT repos/ivankovic/stop-bots/pages --input - <<'JSON'
{"build_type": "legacy", "source": {"branch": "gh-pages", "path": "/"}}
JSON
```

The artifact route is the one to take instead only if this repository ever grows a
second thing to publish — Pages has a single deployment for the whole site, so two
workflows deploying separately would each erase the other. That would mean rebuilding
`pool/` from every past release's `.deb` on every run, since an artifact deploy
replaces the site rather than adding to it, and it is why the accumulating `gh-pages`
branch is the better fit while the apt tree is all there is.

**This step comes after the first release**, not before it. The branch selector only
offers branches that exist, and `gh-pages` is created by the `apt` job on its first
run. So the first release publishes a repository that nothing is serving yet, and
pointing Pages at the branch afterwards makes it live — every release after that needs
nothing.

If you would rather have the URL working before the first release, create the branch
by hand first and then configure Pages:

```sh
git switch --orphan gh-pages
git commit --allow-empty -m "apt: start the repository branch"
git push -u origin gh-pages
git switch main
```

Either way, nothing is needed on the workflow side: `release.yml` creates the branch
as an orphan if it is missing and reuses it if it is not.

Check it once, after the first release that follows this setup:

```
curl -fsSL https://ivankovic.github.io/stop-bots/key.gpg | gpg --show-keys
curl -fsSL https://ivankovic.github.io/stop-bots/dists/stable/InRelease | head
```

## Releasing

Do all seven steps, in order. An earlier draft of this section claimed the first release
could start at step 3 because the version and changelog were already in place. The version
was; the changelog was not. `0.0.1` had been written against the original scope in August
and then sat untouched while five months of work accumulated under `Unreleased`, so
starting at step 3 would have published a changelog describing a fraction of the code that
shipped with it. Step 2 is cheap to run and the only thing that catches that.

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
   cargo llvm-cov --workspace --fail-under-lines 90 --summary-only
   cargo publish --dry-run
   ```

   And, if any screen's layout changed, regenerate the README's screenshots and
   commit the diff — CI does not do this for you:

   ```
   make screenshots
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

   This builds `x86_64` and `aarch64` Linux binaries — statically linked against musl,
   so one package serves every distribution — creates the GitHub release with a tarball,
   a `.deb` and a SHA-256 for each, and then republishes the APT repository with both
   `.deb`s added. Releases with a `v0.0.` prefix are marked pre-release automatically.

   Watch the `apt` job specifically. It runs last and is the only step that writes to
   `gh-pages`, so it is the one whose failure leaves the two publications disagreeing.

6. **Watch the release build finish**, then publish the crate:

   ```
   cargo publish
   ```

7. **Update the hand-maintained distribution packages** — the AUR ones and the Gentoo
   ebuild. They consume artefacts that only exist once steps 5 and 6 are done — the
   GitHub release tarball and the crates.io `.crate` — so they are genuinely last, not
   merely listed last. `packaging/README.md` has the checksum commands and the
   submission steps for each.

   Debian and Ubuntu are **not** in this step: the `.deb`s were built and published by
   step 5. `packaging/README.md` says which packages need a human and which do not.

If something is wrong before step 6, delete the tag and the release, fix it, and start
again:

```
git push --delete origin v0.0.1
git tag -d v0.0.1
```

Deleting the tag does not unpublish the APT repository, because that lives on a branch
rather than on the tag. If the bad version reached it, remove it from `gh-pages` and let
the next release rebuild the indices:

```
git clone --branch gh-pages <repo> pages && cd pages
git rm pool/main/s/stop-bots/stop-bots_0.0.1-1_*.deb
git commit -m "apt: withdraw 0.0.1" && git push
```

The indices still list it until something regenerates them, so run
`scripts/build-apt-repo.sh` over the checkout afterwards, or re-run the `apt` job. The
script rebuilds every index from whatever is in `pool/`, which is what makes a removal
take effect at all.

## When only the `apt` job fails

The GitHub release is complete and the `.deb`s are attached to it — the repository is
simply a release behind. Re-run the failed job from the Actions tab; it re-downloads the
artefacts from the same run, so nothing has to be rebuilt and a second run publishes the
same bytes. If the artefacts have expired, re-push the tag.

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

## The README's claims

Three things in `README.md` are only true after a release, and all three are checked
by something rather than by memory:

- **`cargo install stop-bots`** works only once `cargo publish` has run. Until then
  the crates.io badge renders as an error, which is the visible reminder.
- **The releases link** is empty until the first tag is pushed.
- **The coverage badge** claims a floor that the `coverage` CI job enforces with
  `--fail-under-lines`.

The first two are why the announcement goes out after step 6, not before it.

All three hold as of `0.0.1`, published 2026-09-14: the badge resolves, the releases page
has the `x86_64` tarball and its checksum, and the coverage job is green. They are listed
here because each *release* has to re-establish them, not because any of them is still
outstanding. A badge that has gone back to rendering an error means the publish did not
land, whatever the terminal said.
