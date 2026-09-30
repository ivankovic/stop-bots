#!/bin/sh
# Prints the Debian package version for a Cargo version: the one in
# Cargo.toml, or the one given as the first argument.
#
#   0.1.0        -> 0.1.0-1
#   0.1.0-rc.1   -> 0.1.0~rc.1-1
#
# Why this exists: cargo-deb turned `0.1.0-rc.1` into `0.1.0.rc.1-1`, and
# Debian sorts that *after* `0.1.0-1` — so a host that installed the
# release candidate would never upgrade to the release. A `~` sorts before
# everything, including the end of the string, which is exactly what a
# pre-release means. Only the first `-` separates a semver pre-release, so
# only that one becomes `~`; the `-1` is the Debian revision cargo-deb
# would have added.
set -e

version="$1"
if [ -z "$version" ]; then
    version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$(dirname "$0")/../Cargo.toml" | head -n 1)
fi
[ -n "$version" ] || { echo "deb-version: no version found" >&2; exit 1; }

# Build metadata (`+…`) has no meaning to Debian's ordering; drop it.
version="${version%%+*}"

case "$version" in
    *-*) echo "${version%%-*}~${version#*-}-1" ;;
    *) echo "${version}-1" ;;
esac
