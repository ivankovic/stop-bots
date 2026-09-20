#!/bin/sh
#
#  This file is part of the stop-bots project.
#
#  Copyright (C) 2026 Marko Ivankovic
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Affero General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Builds and signs the APT repository served from GitHub Pages.
#
#  Usage: build-apt-repo.sh <repo-dir> <deb-dir> <gpg-key-id>
#
#    repo-dir    a checkout of the `gh-pages` branch, which already holds
#                every previously released .deb
#    deb-dir     the .debs built by this run, to be added to it
#    gpg-key-id  the signing key, already imported into the keyring
#
#  It lives here rather than inside the workflow for the same reason
#  `deploy-remote.sh` does: it is branching shell whose failure modes are
#  worth reading, and a `.sh` file can be run by hand against a local
#  directory when something about a published repository looks wrong.
#
#  ## Why it regenerates rather than appends
#
#  Every index below is rebuilt from whatever is in `pool/` right now, not
#  patched. An APT index is a set of checksums over a set of files, so
#  there is no correct way to add one package to it without recomputing
#  the rest -- and a half-updated index is not a repository with one
#  package missing, it is one `apt` refuses to use at all. Rebuilding is
#  also what makes a re-run after a failed publish a no-op rather than a
#  second copy of everything.
#
#  This does mean the `gh-pages` checkout is the archive: every version
#  ever published lives in it, and losing that branch loses the ability to
#  install an older version. The .debs are on the GitHub releases too, so
#  the loss would be recoverable, but it would be recoverable by hand.

set -eu

REPO_DIR="${1:?usage: build-apt-repo.sh <repo-dir> <deb-dir> <gpg-key-id>}"
DEB_DIR="${2:?missing <deb-dir>}"
GPG_KEY="${3:?missing <gpg-key-id>}"

# One suite and one component. A repository serving a single project has
# nothing to put in a second of either, and `stable` is the name every
# example on the internet uses, so a user who mistypes the sources.list
# line still lands on the one that exists.
SUITE=stable
COMPONENT=main

# Both are built natively on their own runner; see release.yml for why
# there is no cross-compilation here.
ARCHITECTURES="amd64 arm64"

# Signs one file with the release key, with or without a passphrase on it.
#
# `GPG_PASSPHRASE` is read from the environment rather than passed as an
# argument, and then handed to gpg on stdin rather than on its command
# line: `--passphrase <value>` puts the passphrase in gpg's argv, where
# anything that can read /proc on the same machine can recover it. A
# GitHub runner is not a shared machine, so this is a small risk -- it is
# just not one worth taking for the one line it costs to avoid.
#
# An empty passphrase means the key has none, which is a defensible choice
# for a key that exists only as a CI secret, but only as a decision rather
# than an accident -- RELEASING.md says which one this key is.
sign() {
    if [ -n "${GPG_PASSPHRASE:-}" ]; then
        printf '%s' "${GPG_PASSPHRASE}" | gpg --batch --yes \
            --pinentry-mode loopback --passphrase-fd 0 \
            --local-user "${GPG_KEY}" "$@"
    else
        gpg --batch --yes --local-user "${GPG_KEY}" "$@"
    fi
}

if ! command -v apt-ftparchive >/dev/null 2>&1; then
    echo "apt-ftparchive not found: install apt-utils" >&2
    exit 1
fi

# `pool/main/s/stop-bots/` is Debian's own layout: component, then the
# first letter of the source package, then the package. Nothing requires
# it of a third-party repository -- `Filename:` in the index is what
# actually locates a .deb -- but matching it means anyone who has looked
# at a Debian mirror already knows where to find things here.
POOL="pool/${COMPONENT}/s/stop-bots"
mkdir -p "${REPO_DIR}/${POOL}"

echo "Adding new packages to the pool:"
found_deb=0
for deb in "${DEB_DIR}"/*.deb; do
    [ -e "$deb" ] || continue
    found_deb=1
    echo "  $(basename "$deb")"
    cp -f "$deb" "${REPO_DIR}/${POOL}/"
done
if [ "$found_deb" -eq 0 ]; then
    echo "No .deb files in ${DEB_DIR} -- nothing to publish." >&2
    exit 1
fi

cd "${REPO_DIR}"

# Clear the signatures and the Release file before regenerating. The
# `release` command below hashes every file it finds under `dists/`, so
# leaving the previous run's `Release`, `Release.gpg` and `InRelease` in
# place would hash those too -- a Release file listing a checksum of the
# Release file that preceded it, which is both meaningless and confusing
# to debug.
rm -f "dists/${SUITE}/Release" "dists/${SUITE}/Release.gpg" "dists/${SUITE}/InRelease"

for arch in ${ARCHITECTURES}; do
    dir="dists/${SUITE}/${COMPONENT}/binary-${arch}"
    mkdir -p "$dir"
    # `--arch` filters the pool by the package's own Architecture field,
    # so one pool feeds every per-architecture index and the .debs are
    # stored once rather than once per index that mentions them.
    apt-ftparchive --arch "$arch" packages "${POOL}" > "${dir}/Packages"
    gzip -9nc "${dir}/Packages" > "${dir}/Packages.gz"
    echo "  ${dir}/Packages: $(grep -c '^Package:' "${dir}/Packages") package(s)"
done

# No `Valid-Until`, deliberately. It is the field that tells apt to stop
# trusting an index after a date, and it is right for a distribution that
# republishes daily: a stale mirror is a real attack surface there. This
# repository is republished only when there is a release, so a
# `Valid-Until` would mean `apt update` starts failing on every machine
# some weeks after the last one -- turning a quiet period into an outage
# for people who did nothing but not upgrade.
apt-ftparchive \
    -o APT::FTPArchive::Release::Origin="stop-bots" \
    -o APT::FTPArchive::Release::Label="stop-bots" \
    -o APT::FTPArchive::Release::Suite="${SUITE}" \
    -o APT::FTPArchive::Release::Codename="${SUITE}" \
    -o APT::FTPArchive::Release::Components="${COMPONENT}" \
    -o APT::FTPArchive::Release::Architectures="${ARCHITECTURES}" \
    -o APT::FTPArchive::Release::Description="stop-bots -- stop bad bots without hiding behind a CDN" \
    release "dists/${SUITE}" > "dists/${SUITE}/Release"

# Both signature forms, because which one apt fetches is not ours to
# choose. Modern apt asks for `InRelease` (the clearsigned index, one
# round trip); anything older, and some proxies, fall back to `Release`
# plus a detached `Release.gpg`. Publishing only the first silently
# excludes the clients that need the second.
sign --clearsign --output "dists/${SUITE}/InRelease" "dists/${SUITE}/Release"
sign --detach-sign --armor --output "dists/${SUITE}/Release.gpg" "dists/${SUITE}/Release"

# The public key, dearmored, at a stable URL. `signed-by` in a sources
# entry wants the binary form, and pointing it at an ASCII-armoured file
# is the single most common reason a correct-looking sources.list still
# reports NO_PUBKEY.
gpg --export "${GPG_KEY}" > key.gpg

echo
echo "Signed ${SUITE} with ${GPG_KEY}. Repository contents:"
find dists pool -type f | sort | sed 's/^/  /'
