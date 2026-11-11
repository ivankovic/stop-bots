# Releasing

Two publications happen per release, and they are deliberately not the same step:

| Target   | Trigger                    | Reversible?                                     |
| -------- | -------------------------- | ----------------------------------------------- |
| GitHub   | pushing a `v*` tag         | yes — delete the tag and the release, re-push    |
| APT      | the same tag               | yes — revert the `gh-pages` commit               |
| dnf      | the same tag               | yes — revert the `gh-pages` commit               |
| crates.io| running `cargo publish`    | **no** — a version can be yanked, never replaced |

The APT and dnf repositories ride along with the GitHub release: the same workflow
builds the `.deb`s and `.rpm`s and publishes them, so there is no third step to
remember. They are listed separately only because each can fail on its own, and what to
do about that is at the bottom of this file.

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

The dnf repository is signed with the same key, by the `dnf` job, so it needs no setup
of its own: the secrets below serve both. It signs each `.rpm` it publishes and the
index (`repomd.xml.asc`), and publishes the key armoured as `key.asc`, which is what
`rpm --import` reads. One key for both keeps one thing to back up and one fingerprint
to announce.

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

Do all eight steps, in order. An earlier draft of this section claimed the first release
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

   The heading is `## [x.y.z] — <date>`, with the version exactly as tagged, and a
   release candidate gets one of its own: `## [0.1.0-rc.1]` for `v0.1.0-rc.1`, as
   every candidate so far has. The release workflow refuses a tag whose version has no
   such heading, and publishes the section under it as the release notes
   (`scripts/changelog-section.py` prints exactly what it will publish), so write it
   for the people upgrading.

   **For `0.2.0`, the release that adds Apache:** the section has to tell Apache hosts
   that they cannot go back to `0.1.x` by installing the older package. `set-web-server`
   writes `web_server` (and, for Apache, `apache_*`) keys to
   `/etc/stop-bots/host.conf`; `0.1.x` refuses a key it does not know, so everything
   that reads that file fails with an error naming the line. With the keys deleted it
   runs, but treats the host as NGINX and does not recognise the blocks `0.2.0` wrote
   into the Apache config. The way back is, under `0.2.0`, `sudo stop-bots uninstall
   web-server`, then deleting those keys, then the downgrade. The same holds if `0.2.0`
   itself is withdrawn (below): removing it from the APT repository does not take an
   Apache host back, and the hosts that already installed it need the same three steps.

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

   This first checks the tag against `Cargo.toml` and `CHANGELOG.md`, runs the test
   suite on `x86_64` and `aarch64` runners, and only if both pass builds `x86_64` and
   `aarch64` Linux binaries — statically linked against musl, so one package serves
   every distribution. Then, in order:

   - it attests build provenance for every tarball, `.deb` and `.rpm` (see
     [Verifying a download](#verifying-a-download));
   - it creates the GitHub release: per architecture a tarball (the binary, README,
     licence, man pages and completions), a `.deb` and an `.rpm`, a `.sha256` beside
     each, one `SHA256SUMS` over all of them, and the changelog section as the notes;
   - it republishes the APT repository with both `.deb`s added;
   - and then the dnf repository with both `.rpm`s, signed, added.

   A release is marked pre-release if its tag starts with `v0.0.` or has a semver
   pre-release part — a release candidate, `v0.1.0-rc.1`. A candidate also stays out of
   both repositories, which have one channel each; its `.deb`s and `.rpm`s are on its
   GitHub release.

   Watch the `apt` and `dnf` jobs specifically. They run last and are the only steps
   that write to `gh-pages`, so they are the ones whose failure leaves the publications
   disagreeing. `dnf` waits for `apt`, so the two never push at once, but runs whether
   or not `apt` succeeded.

6. **Watch the release build finish**, then publish the crate:

   ```
   cargo publish
   ```

7. **Update the hand-maintained distribution packages** — the AUR ones and the Gentoo
   ebuild. They consume artefacts that only exist once steps 5 and 6 are done — the
   GitHub release tarballs and the crates.io `.crate` — so they are genuinely last, not
   merely listed last. One script rewrites all three from what was published:

   ```
   python3 packaging/bump.py 0.0.1
   git add packaging && git commit -m "packaging: 0.0.1"
   ```

   It fetches the published checksums (network reads only), writes both PKGBUILDs and
   their `.SRCINFO`, and generates the ebuild from the tag: `CRATES` from its
   `Cargo.lock`, `LICENSE` and `RUST_MIN_VER` from `cargo metadata`. Submitting to the
   AUR and the overlay stays manual; `packaging/README.md` has the steps for each.

   Debian and Ubuntu are **not** in this step: the `.deb`s were built and published by
   step 5. `packaging/README.md` says which packages need a human and which do not.

8. **Add the release's upgrade fixture**, so every later release is tested against
   what this one wrote. Download the published `x86_64` tarball into an empty directory
   outside the checkout, check it against `SHA256SUMS`, and record what that binary
   writes:

   ```
   scripts/upgrade-fixture.sh /tmp/sb-0.0.1/stop-bots-0.0.1-x86_64-unknown-linux-musl/stop-bots 0.0.1
   ```

   The script's header has the download commands. It writes
   `tests/fixtures/db/db-0.0.1.sql` and `tests/fixtures/upgrade/0.0.1/`; add `"0.0.1"`
   to `RELEASES` in `tests/upgrade.rs`, run `cargo test --test upgrade`, and commit the
   three together. Use the released binary, not one built from the tag: the fixture is
   evidence of what users actually installed.

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

The dnf side is the same, under `rpm/packages/`:

```
git rm rpm/packages/stop-bots-0.0.1-1.*.rpm
git commit -m "dnf: withdraw 0.0.1" && git push
```

and then rebuild and re-sign the index, as `scripts/build-rpm-repo.sh` would (it stops
when given no new package, so it cannot do a removal by itself):

```
createrepo_c --general-compress-type gz --update rpm/
gpg --local-user 5760551466101E868D04F50235F63282482780A7 --yes \
    --detach-sign --armor rpm/repodata/repomd.xml
git add -A && git commit -m "dnf: reindex without 0.0.1" && git push
```

## When only the `apt` or `dnf` job fails

The GitHub release is complete and the `.deb`s and `.rpm`s are attached to it — the
repository is simply a release behind. Re-run the failed job from the Actions tab; it re-downloads the
artefacts from the same run, so nothing has to be rebuilt and a second run publishes the
same bytes. If the artefacts have expired, re-push the tag.

After step 6 the version is spent — `cargo yank` hides it from new dependants but does not
free the number.

## A note on `Cargo.lock`

It is tracked, and the release build passes `--locked` while CI's test job does not. That
is the right way round — CI catches a dependency that has drifted, the release build is
reproducible — but it does mean a green test job is not proof that the release build
will resolve the same tree. The MSRV job is the exception and does pass `--locked`: it
exists to say whether the shipped tree builds on the oldest supported Rust, so it has
to check that tree. In practice this only bites if a dependency is yanked between the
two.

## Versioning

The version number describes the program, not the Rust library, and follows
[semver](https://semver.org) strictly: a patch release fixes things, a minor release
adds things, and only a major release takes anything away. `0.x` minors were allowed to
break; from `1.0.0` on, nothing in the contract below breaks before `2.0.0`.

### The contract

- **The command line:** every verb and flag, the values each accepts, and what each
  does. Exit codes: `0` for success, non-zero for a failure or a refusal (a lockout
  guard that refuses an apply exits non-zero, which is what makes cron mail someone).
- **The JSON output** of `status --json` and every `list-* --json`: fields may be added,
  never renamed, retyped or removed, and the spelling of enumerated values (`"block"`,
  `"critical"`) stays what it is. Free text inside a field, such as a check's `detail`
  and `fix`, is human-readable output and may change.
- **The database:** a release opens every database an earlier release wrote, with the
  settings in it intact, and a database a `1.x.y` release has used can still be opened
  by the release before it in the same minor, so going back one patch release is safe.
  Settings keys keep their names.
- **The files it writes:** the NGINX and Apache blocks it injects, the managed `conf.d`
  files, the firewall script, the systemd units (`stop-bots-firewall.service` and the
  rest) and `/etc/cron.d/stop-bots`, including the markers it finds its own text by
  (`# BEGIN stop-bots (DO NOT EDIT)` and its siblings). Output *between* the markers
  may change, as long as the next release recognises and replaces what the previous one
  wrote.
- **The paths it uses:** `/var/lib/stop-bots`, `/etc/stop-bots` and the files in them,
  and every other default location.
- **`STOP_BOTS_DB`**, the one environment variable meant for users. The others
  (`STOP_BOTS_NGINX_DIR`, `STOP_BOTS_HOST_CONF`, `STOP_BOTS_SSH_CLIENT` and the like) are
  hooks for the test suite and can change in any release.

### Not in the contract

- **The TUI:** its keys, screens and layout. They are for a person, who adapts, and
  freezing them would stop it getting easier to use.
- **The wording of human-readable output**, on the terminal or in the TUI. A script
  that needs to read output uses `--json`.
- **The Rust library.** `src/lib.rs` makes every module `pub` so that `main.rs`,
  `tests/` and `examples/` can reach them. The modules are `#[doc(hidden)]`, the crate
  documentation says there is no supported Rust API, and any of it can change in any
  release, patch releases included. The product is the binary; a designed library would
  be a second product with its own users, and nobody has asked for one.

### Breaking, adding and deprecating

**Breaking** means:

- removing or renaming a verb, a flag or a JSON field;
- changing what an existing verb or flag does in a way a script relying on it would
  notice, including its exit code;
- writing a database that the previous patch release cannot open or would misread;
- changing a generated-file marker or a default path, so that a newer release no longer
  recognises what an older one wrote (or the other way round).

Adding a verb, a flag, a setting or a JSON field is not breaking.

**Deprecating** is how something leaves without breaking anyone:

1. In any minor release, the old name becomes a hidden alias of the new one (a hidden
   clap alias for a verb or flag) and keeps working exactly as before.
2. Using it prints one line to stderr: `warning: --old is deprecated, use --new; it will
   be removed in 2.0.0`. Cron mails stderr, so a host run unattended hears about it
   without anyone reading a changelog.
3. The changelog lists it under **Deprecated** in that release.
4. It is removed in the next major release, and listed under **Removed** there.

Before `1.0.0` the same rules held within a minor (`0.1.x`, `0.2.x`); `0.x` minors could
break, and `0.2.0` did. Going back across a minor release is not part of the contract.
In particular an Apache host cannot go back from `0.2.0` to `0.1.x` without removing what
`0.2.0` wrote first; step 2 above has the details, and the `0.2.0` changelog repeats them.

### Supported platforms and Rust

- **Platforms:** Debian and Ubuntu with systemd, from the APT repository, the release
  binaries or `cargo install`. The RPM is checked to install and upgrade on Fedora and
  Rocky Linux 8 and 9 (CI's `rpm` job); stop-bots itself is not tested there. Arch Linux through the AUR and Gentoo through GURU, once
  each is published from `packaging/`. Anything else may work (the binaries are static)
  but is not tested.
- **Security fixes** go into a new release of the latest minor only; nothing is
  backported (see `SECURITY.md`).
- **The MSRV** in `Cargo.toml` (`rust-version`) is enforced by a dedicated CI job. A
  minor release may raise it, and says so in the changelog; a patch release never does.
  A dependency raising *its* MSRV shows up as that job going red.

## The README's claims

Three things in `README.md` are only true after a release, and all three are checked
by something rather than by memory:

- **`cargo install stop-bots`** works only once `cargo publish` has run. Until then
  the crates.io badge renders as an error, which is the visible reminder.
- **The releases link** is empty until the first tag is pushed.
- **The coverage badge** claims a floor that the `coverage` CI job enforces with
  `--fail-under-lines`.

The first two are why the announcement goes out after step 6, not before it.

All three have held since `0.0.1`, published 2026-09-14, and were last checked for
`0.1.1`, published 2026-10-01: crates.io has it, and its release page has the tarballs
and the `.deb`s for both architectures. They are listed here because each *release*
has to re-establish them, not because any of them is still outstanding. A badge that has
gone back to rendering an error means the publish did not land, whatever the terminal
said.

## Verifying a download

This section is written to be linked to from the README.

The APT and dnf repositories need nothing from you: `apt` checks every package against
the index that `signed-by` pins, and `dnf` checks both the index and each package's own
signature against the key it asked you to import, and each refuses one that does not
match. What follows is for a
file downloaded from a GitHub release page by hand.

**That it arrived intact.** Each asset has a `.sha256` beside it, and `SHA256SUMS`
covers all of them:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

**That this repository's release workflow built it.** Every tarball, `.deb` and `.rpm` has a
build provenance attestation: a statement, signed through Sigstore with a certificate
issued to `release.yml` in `ivankovic/stop-bots` and logged publicly, of which commit
and which workflow run produced that exact file. GitHub's CLI checks it:

```sh
gh attestation verify stop-bots-0.2.0-x86_64-unknown-linux-musl.tar.gz \
  --repo ivankovic/stop-bots \
  --signer-workflow ivankovic/stop-bots/.github/workflows/release.yml
```

It fails if the file was built anywhere else or changed afterwards; with `--format
json` it also shows the commit and the workflow run that built it. A checksum can only say a file matches the
one on the release page; the attestation says where that one came from, which is the
question that matters if the release page itself were tampered with. `gh` has to be
logged in (`gh auth login`) to fetch the attestation.

Attestations exist from the release after `0.1.1` on, and for `.rpm`s from the first
release that has them. The assets are not GPG-signed: the only key the project has is
the repositories', and it is kept to the two jobs that sign them. That includes the
`.rpm`s on the release page; the copies in the dnf repository are signed, and differ
from them only in that signature, which lives in the RPM header and leaves the payload
as attested.
