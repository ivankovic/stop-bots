#!/usr/bin/env python3
"""Regenerate the Gentoo ebuild's CRATES list from Cargo.lock.

Gentoo's cargo.eclass wants every transitive crate enumerated by name and
version, because the package manager — not cargo — is what fetches them.
This tree has ~340, so the list is generated rather than maintained.

Run after every version bump:

    python3 packaging/gentoo/gen-ebuild.py

and rename the output to match the new version. The LICENSE line is *not*
generated: see the comment in the template.
"""

import pathlib
import re
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
LICENSE="AGPL-3.0+"
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


def crates_from_lock(path: pathlib.Path) -> list[str]:
    text = path.read_text()
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


def main() -> int:
    lock = ROOT / "Cargo.lock"
    if not lock.exists():
        print(f"no Cargo.lock at {lock}", file=sys.stderr)
        return 1

    version = re.search(
        r'^version = "(.+)"', (ROOT / "Cargo.toml").read_text(), re.M
    ).group(1)

    crates = crates_from_lock(lock)
    body = TEMPLATE.format(crates="\n".join(f"\t{c}" for c in crates))

    dest = pathlib.Path(__file__).parent / f"stop-bots-{version}.ebuild"
    dest.write_text(body)
    print(f"wrote {dest.relative_to(ROOT)} ({len(crates)} crates)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
