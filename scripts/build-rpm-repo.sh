#!/bin/sh
#
#  This file is part of the stop-bots project.
#
#  Copyright (C) 2026 Marko Ivankovic
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Affero General Public License as published
#  by the Free Software Foundation, version 3 of the License.
#
#  Builds and signs the dnf repository served from GitHub Pages, beside the
#  APT one that build-apt-repo.sh writes, with the same key.
#
#  Usage: build-rpm-repo.sh <repo-dir> <rpm-dir> <gpg-key-id>
#
#    repo-dir    a checkout of the `gh-pages` branch, which already holds
#                every previously released .rpm under rpm/packages/
#    rpm-dir     the .rpms built by this run, to be signed and added to it
#    gpg-key-id  the signing key, already imported into the keyring
#
#  ## Two signatures, and why both
#
#  Each package is signed (`rpmsign`), and so is the index that lists them
#  (`repomd.xml.asc`). dnf checks the first with `gpgcheck=1`, which is the
#  default every Fedora and RHEL user has and the one a repository asking
#  for `gpgcheck=0` would rightly be distrusted for. The second,
#  `repo_gpgcheck=1`, is what stops a mirror from serving an older index
#  that still lists a version with a known hole: the packages in it would
#  all verify. APT gets both from its one signed Release file.
#
#  Only the packages added by this run are signed. The ones already in the
#  branch were signed when they were published, and re-signing them would
#  change their bytes for no reason anyone downloading them could see.
#
#  The packages on the GitHub release page are the unsigned ones, as the
#  .debs and tarballs there are: what vouches for those is the checksum
#  and the build provenance attestation (RELEASING.md, "Verifying a
#  download"), and the key stays in the jobs that publish a repository.
#  A signature lives in the RPM header, so the signed copy here has the
#  same payload, byte for byte, as the attested one.
#
#  ## Why it regenerates rather than appends
#
#  For the reason build-apt-repo.sh gives: the metadata is checksums over
#  every package, rebuilt from what is in rpm/packages/ now, so a re-run
#  after a failed publish changes nothing.

set -eu

REPO_DIR="${1:?usage: build-rpm-repo.sh <repo-dir> <rpm-dir> <gpg-key-id>}"
RPM_DIR="${2:?missing <rpm-dir>}"
GPG_KEY="${3:?missing <gpg-key-id>}"

# One repository for both architectures. dnf picks the packages whose arch
# it can install, so a second tree per arch would only be a second thing
# for the .repo file to get wrong.
PACKAGES="rpm/packages"

for tool in createrepo_c rpmsign gpg; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "$tool not found: install createrepo-c and rpm" >&2
        exit 1
    fi
done

# See build-apt-repo.sh's `sign()` for why the passphrase goes to gpg on a
# descriptor rather than its command line. rpmsign runs gpg itself, so it
# gets the passphrase from a file only this user can read, removed on exit.
passfile=""
cleanup() { [ -z "$passfile" ] || rm -f "$passfile"; }
trap cleanup EXIT
gpg_extra="--batch"
if [ -n "${GPG_PASSPHRASE:-}" ]; then
    passfile=$(mktemp)
    chmod 600 "$passfile"
    printf '%s' "${GPG_PASSPHRASE}" > "$passfile"
    gpg_extra="--batch --pinentry-mode loopback --passphrase-file ${passfile}"
fi

mkdir -p "${REPO_DIR}/${PACKAGES}"

echo "Signing and adding new packages:"
found_rpm=0
for rpm in "${RPM_DIR}"/*.rpm; do
    [ -e "$rpm" ] || continue
    found_rpm=1
    dest="${REPO_DIR}/${PACKAGES}/$(basename "$rpm")"
    cp -f "$rpm" "$dest"
    # SHA-256 said outright: RHEL 9's default crypto policy refuses a
    # signature made over SHA-1, and rpmsign's default has varied between
    # versions.
    # `__gpg` too: Ubuntu's rpm looks for gpg where Fedora puts it, and
    # fails with "Could not exec gpg" on the runner otherwise.
    rpmsign --addsign \
        --define "__gpg $(command -v gpg)" \
        --define "_gpg_name ${GPG_KEY}" \
        --define "_gpg_digest_algo sha256" \
        --define "_gpg_sign_cmd_extra_args ${gpg_extra}" \
        "$dest" >/dev/null
    echo "  $(basename "$rpm")"
done
if [ "$found_rpm" -eq 0 ]; then
    echo "No .rpm files in ${RPM_DIR} -- nothing to publish." >&2
    exit 1
fi

cd "${REPO_DIR}/rpm"

# gzip, not createrepo_c's newer default of zstd: dnf on EL8 cannot read
# zstd-compressed metadata, and these files are small enough that the
# difference is not worth a distribution.
createrepo_c --quiet --general-compress-type gz --update .

# A detached, armoured signature next to the index is where dnf looks for
# one when `repo_gpgcheck=1`.
rm -f repodata/repomd.xml.asc
if [ -n "$passfile" ]; then
    gpg --batch --yes --pinentry-mode loopback --passphrase-file "$passfile" \
        --local-user "${GPG_KEY}" --detach-sign --armor repodata/repomd.xml
else
    gpg --batch --yes --local-user "${GPG_KEY}" --detach-sign --armor repodata/repomd.xml
fi

cd "${REPO_DIR}"

# The public key armoured, because `rpm --import` (which dnf uses for the
# package signatures) does not read the binary key.gpg the APT side
# publishes. Same key, same fingerprint.
gpg --armor --export "${GPG_KEY}" > key.asc

echo
echo "Signed rpm/ with ${GPG_KEY}. Repository contents:"
find rpm -type f | sort | sed 's/^/  /'
