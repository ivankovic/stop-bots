#!/usr/bin/env python3
"""Regenerate the Gentoo ebuild's CRATES list from Cargo.lock.

Gentoo's cargo.eclass wants every transitive crate enumerated by name and
version, because the package manager — not cargo — is what fetches them.
This tree has ~400, so the list is generated rather than maintained.

For a released version, name it:

    python3 packaging/gentoo/gen-ebuild.py 0.0.15

which reads Cargo.lock from the `v0.0.15` tag rather than from the working
tree. The ebuild builds that tag's source archive, so its CRATES must be that
tag's lock file; the working tree's has usually moved on by the time the
release is out. `packaging/bump.py` runs this for you.

With no argument it uses the working tree's Cargo.toml version and Cargo.lock,
for trying an unreleased tree in a local overlay.

The LICENSE line is *not* generated: see the comment in the template.
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

TEMPLATE = '''# Copyright 2026 Marko Ivankovic
# Distributed under the terms of the GNU Affero General Public License v3

EAPI=8

# Generated from Cargo.lock by packaging/gentoo/gen-ebuild.py. Do not edit by
# hand — regenerate after a version bump.
CRATES="
{crates}
"

inherit cargo

DESCRIPTION="A TUI that helps you configure your server to stop bad bots and still allow good bots"
HOMEPAGE="https://github.com/ivankovic/stop-bots"
SRC_URI="
	https://github.com/ivankovic/stop-bots/archive/v${{PV}}.tar.gz -> ${{P}}.tar.gz
	${{CARGO_CRATE_URIS}}
"

# The first line is this package. The rest are the dependency tree's, which
# Gentoo requires listed and which this script does NOT compute — Cargo.lock
# records no licences. Regenerate with `pycargoebuild` (app-portage/pycargoebuild)
# and copy its LICENSE line here before submitting anywhere but a personal overlay.
LICENSE="AGPL-3"
LICENSE+=" Apache-2.0 BSD BSD-2 ISC MIT MPL-2.0 Unicode-3.0 ZLIB"

SLOT="0"
KEYWORDS="~amd64"

# rusqlite is built with its `bundled` feature, so SQLite is compiled from
# vendored C sources here rather than linked against dev-db/sqlite. That is a
# toolchain requirement, not a runtime dependency.
DEPEND=""
RDEPEND="${{DEPEND}}"

# The container suite needs Docker and NET_ADMIN; src_test must not.
src_test() {{
	cargo_src_test
}}
'''


def crates_from_lock(text: str) -> list[str]:
    out = []
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'^name = "(.+)"', block, re.M)
        version = re.search(r'^version = "(.+)"', block, re.M)
        # A package with no `source` is this workspace's own crate, which the
        # eclass must not try to fetch from crates.io.
        source = re.search(r'^source = "(.+)"', block, re.M)
        if name and version and source:
            out.append(f"{name.group(1)}@{version.group(1)}")
    return sorted(out)


def lock_at_tag(version: str) -> str:
    """Cargo.lock as it was at the tag `v<version>`."""
    tag = f"v{version}"
    result = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{tag}:Cargo.lock"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"cannot read Cargo.lock at {tag}: {result.stderr.strip()}\n"
            "(is the tag fetched? `git fetch --tags`)"
        )
    return result.stdout


def write_ebuild(version: str, lock_text: str) -> pathlib.Path:
    crates = crates_from_lock(lock_text)
    body = TEMPLATE.format(crates="\n".join(f"\t{c}" for c in crates))

    dest = pathlib.Path(__file__).parent / f"stop-bots-{version}.ebuild"
    dest.write_text(body)
    print(f"wrote {dest.relative_to(ROOT)} ({len(crates)} crates)")
    return dest


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print(f"usage: {argv[0]} [version]", file=sys.stderr)
        return 2

    if len(argv) == 2:
        version = argv[1].removeprefix("v")
        write_ebuild(version, lock_at_tag(version))
        return 0

    lock = ROOT / "Cargo.lock"
    if not lock.exists():
        print(f"no Cargo.lock at {lock}", file=sys.stderr)
        return 1

    version = re.search(
        r'^version = "(.+)"', (ROOT / "Cargo.toml").read_text(), re.M
    ).group(1)
    write_ebuild(version, lock.read_text())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
