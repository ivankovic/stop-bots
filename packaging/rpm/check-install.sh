#!/bin/sh
# Installs stop-bots from a dnf repository built by scripts/build-rpm-repo.sh,
# the way a user following packaging/rpm/stop-bots.repo would, and checks
# what that user is relying on. Run inside a Fedora or RHEL-family
# container, with no network needed:
#
#   docker run --rm -v "$PWD/pages:/pages:ro" \
#     -v "$PWD/packaging/rpm:/rpm:ro" fedora:43 sh /rpm/check-install.sh <old> <new>
#
# /pages is the gh-pages tree the script wrote (rpm/ and key.asc); <old>
# and <new> are two RPM versions in it, the first sorting before the
# second. The CI `rpm` job builds a release candidate of the same version
# as <old>, so the upgrade also proves `~` sorts a candidate first.
set -eu

old="${1:?usage: check-install.sh <old-version> <new-version>}"
new="${2:?missing <new-version>}"

. /etc/os-release
echo "== ${PRETTY_NAME}, rpm $(rpm -q --qf '%{VERSION}' rpm)"

# The published .repo file, pointed at the local tree and nothing else.
repo() {
    sed -e "s#https://ivankovic.github.io/stop-bots/rpm#file://$1/rpm#" \
        -e "s#https://ivankovic.github.io/stop-bots/key.asc#file://$1/key.asc#" \
        /rpm/stop-bots.repo > /etc/yum.repos.d/stop-bots.repo
}
dnf_repo() { dnf -y --disablerepo='*' --enablerepo=stop-bots "$@"; }

repo /pages
dnf_repo install "stop-bots-${old}" > /tmp/install.log 2>&1 \
    || { cat /tmp/install.log; echo "FAIL: install ${old} from the repository"; exit 1; }
echo "installed $(rpm -q stop-bots)"

dnf_repo upgrade stop-bots > /tmp/upgrade.log 2>&1 \
    || { cat /tmp/upgrade.log; echo "FAIL: upgrade from the repository"; exit 1; }
installed="$(rpm -q --qf '%{VERSION}' stop-bots)"
[ "$installed" = "$new" ] \
    || { cat /tmp/upgrade.log; echo "FAIL: upgraded to ${installed}, expected ${new}"; exit 1; }
echo "upgraded to $(rpm -q stop-bots); runs as: $(stop-bots --version)"

# `gpgcheck=1` let it in, which already means it was signed by the key the
# .repo names; this says so in the log.
sig="$(rpm -q --qf '%{RSAHEADER:pgpsig}' stop-bots)"
case "$sig" in
    *"Key ID"*) echo "signed: ${sig}" ;;
    *) echo "FAIL: the installed package carries no signature (${sig})"; exit 1 ;;
esac
rpm -V stop-bots || { echo "FAIL: rpm -V"; exit 1; }

# An index that no longer matches its signature. dnf5 reports the bad
# signature, drops the repository and carries on, so the property to check
# is that nothing installs from it, not dnf's exit code.
dnf -y -q remove stop-bots > /dev/null 2>&1
cp -a /pages /tampered
sed -i 's#<revision>#<revision>9#' /tampered/rpm/repodata/repomd.xml
repo /tampered
dnf clean all > /dev/null
if dnf_repo install stop-bots > /tmp/tampered.log 2>&1; then
    cat /tmp/tampered.log
    echo "FAIL: installed from an index whose signature does not match it"
    exit 1
fi
echo "refused a tampered index"
