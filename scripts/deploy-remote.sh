#!/bin/sh
# The remote half of `make deploy`, piped to the target host over ssh.
#
# A separate file rather than a one-liner in the Makefile because it is
# branching shell that decides whether a host keeps serving the old build,
# and that is a thing worth testing. `tests/container.rs` runs this exact
# script against a real systemd.
#
# Usage: sh deploy-remote.sh <installed-path> <unit>
# Expects <installed-path>.new to already be in place, as scp leaves it.
set -e

path="$1"
unit="$2"
[ -n "$path" ] && [ -n "$unit" ] || { echo "usage: $0 <path> <unit>" >&2; exit 2; }

# Staged next to the target and moved into place rather than written over
# it: replacing a running executable in place fails with ETXTBSY, and a
# rename swaps the directory entry while the running process keeps the old
# inode until it restarts.
chmod 755 "$path.new"
mv "$path.new" "$path"

if systemctl cat "$unit" >/dev/null 2>&1; then
    # Restart if the unit is *enabled*, try-restart if it merely exists.
    # The distinction matters in both directions. `try-restart` alone does
    # nothing to a unit that is enabled but not running, so a deploy onto a
    # host whose console had stopped — crash-looped and been given up on,
    # say — would land the new binary and leave it down, which is the same
    # "everything succeeded and nothing happened" this script exists to
    # stop. `restart` alone would start a service on a host where the
    # console is deliberately run by hand, giving it a second copy
    # competing for the port.
    if [ "$(systemctl is-enabled "$unit" 2>/dev/null)" = enabled ]; then
        systemctl restart "$unit"
    else
        systemctl try-restart "$unit"
    fi
    # Printed, not assumed: a restart that failed should be visible here
    # rather than on the next page load.
    printf 'unit state: '
    systemctl is-active "$unit" || true
    printf 'unit runs:  '
    systemctl show "$unit" -p ExecStart --value |
        sed -n 's/.*argv\[\]=\([^ ]*\).*/\1/p'
else
    echo "no $unit on this host — nothing restarted"
fi

# `--version` cannot tell two builds of the same 0.0.x apart: the way this
# fails is that everything succeeds and the console keeps serving the old
# code, and the only two facts that distinguish that are *where* the unit
# looks and *when* the file landed.
printf 'deployed:   '
ls -l --time-style=+%Y-%m-%dT%H:%M:%SZ "$path" | awk '{print $6, $7}'
