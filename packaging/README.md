# Packaging

Distribution packaging lives here so it is reviewable in the same place as the code.

There are two kinds of thing in this directory, and the difference decides whether
you have to do anything at release time:

| | Built by | Needs a human |
| --- | --- | --- |
| **Debian/Ubuntu** (`apt/`) | the `Release` workflow, on every tag | no |
| **AUR, Gentoo** (`aur/`, `gentoo/`) | `bump.py`, run by hand; these are copies pushed to each distribution's own repository | yes, per release |

Nothing in this directory ships in the crate (`Cargo.toml` excludes it).

## Order of operations

The hand-maintained packages below point at artefacts that only exist after a
release, so that work happens **after** `RELEASING.md` step 6, never before:

1. tag pushed → GitHub release with the tarballs and their `.sha256`, **and** the
   `.deb`s published to the APT repository — all automatic
2. `cargo publish` → the crates.io `.crate` tarball exists
3. *then* `python3 packaging/bump.py <version>` for the AUR and Gentoo packages,
   which consume both

## Debian and Ubuntu

The one route that needs nothing from you: `cargo deb` builds the package from
`[package.metadata.deb]` in `Cargo.toml`, and the `apt` job in
`.github/workflows/release.yml` adds it to the repository served from the
`gh-pages` branch at <https://ivankovic.github.io/stop-bots>.

The man pages (one per verb) and the bash, zsh and fish completions are generated
by the binary, so `cargo deb` needs them first; the release and CI jobs do this:

```
cargo build --release
target/release/stop-bots generate-docs --out target/assets
cargo deb --no-build
```

```
curl -fsSL https://ivankovic.github.io/stop-bots/key.gpg \
  | sudo tee /usr/share/keyrings/stop-bots.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/stop-bots.gpg] \
https://ivankovic.github.io/stop-bots stable main" \
  | sudo tee /etc/apt/sources.list.d/stop-bots.list
sudo apt update && sudo apt install stop-bots
```

Four decisions are worth knowing before changing any of it:

- **The package ships no systemd unit and no maintainer scripts.** `stop-bots
  install web` writes the unit, creates `/var/lib/stop-bots` 0700 and generates the
  console password, behind a `--dry-run` that prints the plan first. A package that
  shipped an enabled unit would start a root-run web console on `apt install`, which
  is the opposite of the rule the rest of the project keeps.
- **It depends on nothing.** The binary is statically linked against musl, which is
  what lets one package install on every Debian and Ubuntu still receiving updates
  instead of one per glibc era. A firewall backend is `Recommends` and NGINX is
  `Suggests` — deliberately weak, because the hosts this tool is *for* very often
  run NGINX in a container and have no `nginx` package at all.
- **`gh-pages` is the archive.** The indices are rebuilt from whatever is in `pool/`
  on each release, so that branch holds every version ever published. Losing it
  means losing the ability to install an older one — recoverable from the GitHub
  releases, but by hand.
- **There is no `Valid-Until`.** A repository republished only on release would
  otherwise start failing `apt update` some weeks after the last one. See
  `scripts/build-apt-repo.sh`, which is where all of this actually happens and is
  runnable by hand against a local directory.

### The signing key

Two repository secrets, both set once:

| Secret | What |
| --- | --- |
| `APT_GPG_PRIVATE_KEY` | the armoured private key, `gpg --armor --export-secret-keys` |
| `APT_GPG_PASSPHRASE` | its passphrase, or unset if the key has none |

`RELEASING.md` has the generation steps and the one-time GitHub Pages setting.
Rotating the key changes the fingerprint users have already pinned with
`signed-by`, so it is a thing to announce rather than a thing to do quietly.

## AUR (Arch)

Two packages, which is the convention:

| Package          | Source                        | For                                            |
| ---------------- | ----------------------------- | ---------------------------------------------- |
| `stop-bots`      | the crates.io `.crate` tarball | people who want it built on their machine       |
| `stop-bots-bin`  | the GitHub release tarball     | people who want it now                          |

A `-git` package building from `main` is deliberately not offered: this tool writes
firewall rules, and an untagged commit is not a thing to point at a production server.

### Bumping the version

One command, after `RELEASING.md` step 6, updates both PKGBUILDs and the Gentoo
ebuild to a released version:

```
python3 packaging/bump.py 0.0.15
```

It sets `pkgver`, resets `pkgrel` to 1, and fills in the checksums from what the
release published, not from a fresh download of the file being checked:

- `stop-bots`: the `.crate`'s sha256, as crates.io recorded it at publish time;
- `stop-bots-bin`: for each architecture the PKGBUILD lists (`x86_64` and
  `aarch64`), the digest in the `.sha256` file the release workflow uploaded next to
  that tarball.

It reads everything before it writes anything, so a release that is only half
published (no crate yet, a tarball missing) stops it with the tree untouched. A
`.SRCINFO` next to a PKGBUILD is regenerated as well, with `makepkg --printsrcinfo`
when makepkg is installed. The script pushes nothing: commit what it wrote here,
then submit as below.

### Submitting

The AUR is a git remote per package. First time, for each of the two:

```
git clone ssh://aur@aur.archlinux.org/stop-bots.git aur-stop-bots
cp packaging/aur/stop-bots/PKGBUILD aur-stop-bots/
cd aur-stop-bots
makepkg --printsrcinfo > .SRCINFO   # required; the AUR rejects a push without it
makepkg -si                         # build it once before inflicting it on anyone
git add PKGBUILD .SRCINFO
git commit -m "Initial import: stop-bots 0.0.15"
git push
```

`.SRCINFO` is generated, must be committed, and must be regenerated on every version
bump — a stale one is the single most common reason an AUR package looks wrong on the
website while building fine locally.

Pushing needs an AUR account with your SSH public key registered at
<https://aur.archlinux.org/account/>.

## Gentoo

`stop-bots-<version>.ebuild` is generated by `gen-ebuild.py`, because Gentoo's
`cargo.eclass` requires every transitive crate enumerated in `CRATES` and this tree has
about 400 of them. `bump.py` (above) regenerates it for a release and removes the
previous one. To do only this half:

```
python3 packaging/gentoo/gen-ebuild.py 0.0.15
```

Given a version, it reads `Cargo.lock` from that version's tag, not from the working
tree: the ebuild builds the tag's source archive, so it must fetch the crates that tag
locked. With no argument it uses the working tree, for trying an unreleased build in
a local overlay.

**This is a personal-overlay ebuild, not a ::gentoo submission.** Two things stand
between it and the main tree, and both are more work than writing the ebuild was:

- **The `LICENSE` line is not generated.** Gentoo requires the licences of the whole
  dependency tree listed, and `Cargo.lock` does not record licences. The line in the
  template is a plausible set, not a computed one. Before submitting anywhere public,
  install `app-portage/pycargoebuild` and take its `LICENSE` line as authoritative.
- **A proxy maintainer.** Getting into `::gentoo` means the
  [proxy-maint](https://wiki.gentoo.org/wiki/Project:Proxy_Maintainers) process — a pull
  request against the gentoo repository with a developer sponsoring it, plus `pkgcheck
  scan` clean and a `Manifest` generated by `ebuild ... manifest`.

Until there is demand, the honest home for this is a personal overlay:

```
# on the target machine
mkdir -p /var/db/repos/local/net-misc/stop-bots
cp packaging/gentoo/stop-bots-0.0.15.ebuild /var/db/repos/local/net-misc/stop-bots/
ebuild /var/db/repos/local/net-misc/stop-bots/stop-bots-0.0.15.ebuild manifest
emerge net-misc/stop-bots
```

`net-misc` is the category chosen because the tool's subject is network traffic;
`net-firewall` would be defensible too, but the NGINX half is not a firewall.
