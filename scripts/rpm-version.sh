#!/bin/sh
# Prints the RPM package version for a Cargo version: the one in Cargo.toml,
# or the one given as the first argument.
#
#   0.1.0        -> 0.1.0
#   0.1.0-rc.1   -> 0.1.0~rc.1
#
# The RPM counterpart of deb-version.sh, and for the same reason: `-` is not
# allowed in an RPM version at all (it separates Version from Release), and
# `~` sorts before everything, the end of the string included, so a host
# that installed the release candidate upgrades to the release. The Release
# field, `1`, is set in Cargo.toml rather than appended here.
set -e

version="$1"
if [ -z "$version" ]; then
    version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$(dirname "$0")/../Cargo.toml" | head -n 1)
fi
[ -n "$version" ] || { echo "rpm-version: no version found" >&2; exit 1; }

# Build metadata (`+…`) has no meaning to RPM's ordering; drop it.
version="${version%%+*}"

case "$version" in
    *-*) echo "${version%%-*}~${version#*-}" ;;
    *) echo "${version}" ;;
esac
