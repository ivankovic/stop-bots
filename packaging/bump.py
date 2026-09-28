#!/usr/bin/env python3
"""Bring the AUR and Gentoo packaging up to a released version.

    python3 packaging/bump.py 0.0.15

Run it after RELEASING.md step 6, never before: it reads what the release
published, and both halves have to exist.

- `aur/stop-bots/PKGBUILD` gets the version and the sha256 of the `.crate`,
  as crates.io records it.
- `aur/stop-bots-bin/PKGBUILD` gets the version and, for every
  `sha256sums_<arch>` it declares, the digest from the `.sha256` file the
  release workflow published next to that architecture's tarball.
- A `.SRCINFO` next to either PKGBUILD is regenerated with
  `makepkg --printsrcinfo` when makepkg is installed, and otherwise has its
  version and checksums rewritten in place.
- `gentoo/stop-bots-<version>.ebuild` is generated from the tag's Cargo.lock
  by gen-ebuild.py, and the previous ebuild is removed.

The checksums are read from what was published rather than computed from a
fresh download: a digest taken from the file you are checking says only that
you downloaded something. The script only reads from the network, and pushes
nothing: submitting to the AUR stays the manual step in packaging/README.md.
"""

import importlib.util
import json
import pathlib
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent

CRATE = "stop-bots"
REPO = "https://github.com/ivankovic/stop-bots"

# crates.io refuses requests without a User-Agent, and asks for one that says
# who is asking. The repository URL says that without naming a person.
USER_AGENT = f"stop-bots packaging/bump.py (+{REPO})"

SHA256 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$")


def fetch(url: str, missing: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise SystemExit(f"{url}: not found. {missing}")
        raise SystemExit(f"{url}: HTTP {e.code}")


def crate_sha256(version: str) -> str:
    """The .crate's sha256, as crates.io recorded it at publish time."""
    body = fetch(
        f"https://crates.io/api/v1/crates/{CRATE}/{version}",
        "Has `cargo publish` run (RELEASING.md step 6)?",
    )
    digest = json.loads(body)["version"]["checksum"]
    if not SHA256.match(digest):
        raise SystemExit(f"crates.io returned {digest!r} as the checksum")
    return digest


def tarball_sha256(version: str, arch: str) -> str:
    """The digest the release workflow published next to one tarball."""
    name = f"{CRATE}-{version}-{arch}-unknown-linux-musl.tar.gz"
    body = fetch(
        f"{REPO}/releases/download/v{version}/{name}.sha256",
        f"Did the release workflow for v{version} publish {name}?",
    )
    fields = body.decode().split()
    # `sha256sum` output: the digest, then the file it is the digest of. The
    # name is checked so a mislabelled asset cannot pass for another one.
    if len(fields) != 2 or not SHA256.match(fields[0]) or fields[1] != name:
        raise SystemExit(f"{name}.sha256 is not a sha256sum line for {name}")
    return fields[0]


def read_var(text: str, var: str) -> str:
    """The value of `var=...` in a PKGBUILD, with one level of quoting removed."""
    match = re.search(rf"^{var}=\(?'?([^')\n]*)'?\)?$", text, re.M)
    if not match:
        raise SystemExit(f"no {var}= line")
    return match.group(1)


def set_var(text: str, var: str, value: str, array: bool = False) -> str:
    new = f"{var}=('{value}')" if array else f"{var}={value}"
    text, n = re.subn(rf"^{var}=.*$", new, text, count=1, flags=re.M)
    if n != 1:
        raise SystemExit(f"no {var}= line")
    return text


def bump_pkgbuild(path: pathlib.Path, version: str, sums: dict[str, str]) -> None:
    """Rewrite pkgver, pkgrel and the listed sha256sums variables in place."""
    text = path.read_text()
    old_version = read_var(text, "pkgver")
    old_sums = {var: read_var(text, var) for var in sums}

    if old_version != version:
        text = set_var(text, "pkgver", version)
        text = set_var(text, "pkgrel", "1")
    for var, digest in sums.items():
        text = set_var(text, var, digest, array=True)
    path.write_text(text)
    print(f"wrote {path.relative_to(ROOT)} ({old_version} -> {version})")

    srcinfo = path.with_name(".SRCINFO")
    if srcinfo.exists():
        write_srcinfo(srcinfo, old_version, version, old_sums, sums)


def write_srcinfo(
    path: pathlib.Path,
    old_version: str,
    version: str,
    old_sums: dict[str, str],
    sums: dict[str, str],
) -> None:
    if shutil.which("makepkg"):
        out = subprocess.run(
            ["makepkg", "--printsrcinfo"],
            cwd=path.parent,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        path.write_text(out)
        print(f"wrote {path.relative_to(ROOT)} (makepkg --printsrcinfo)")
        return

    # No makepkg here. .SRCINFO is `key = value` lines, and a bump changes
    # only the version (in pkgver, source and provides), pkgrel and the
    # checksums, so rewrite exactly those.
    lines = []
    for line in path.read_text().splitlines():
        key, sep, value = line.strip().partition(" = ")
        if sep and key == "pkgver":
            value = version
        elif sep and key == "pkgrel" and old_version != version:
            value = "1"
        elif sep and key in sums and value == old_sums[key]:
            value = sums[key]
        elif sep and (key.startswith("source") or key == "provides"):
            # Bounded, so bumping 0.0.1 leaves a "0.0.15" elsewhere alone.
            value = re.sub(
                rf"(?<![\d.]){re.escape(old_version)}(?![\d])", version, value
            )
        else:
            lines.append(line)
            continue
        indent = line[: len(line) - len(line.lstrip())]
        lines.append(f"{indent}{key} = {value}")
    path.write_text("\n".join(lines) + "\n")
    print(f"wrote {path.relative_to(ROOT)} (rewritten; run makepkg --printsrcinfo to check)")


def bin_arches(pkgbuild: pathlib.Path) -> list[str]:
    """The architectures the -bin PKGBUILD carries a checksum for."""
    found = re.findall(r"^sha256sums_(\w+)=", pkgbuild.read_text(), re.M)
    if not found:
        raise SystemExit(f"{pkgbuild}: no sha256sums_<arch>= lines")
    return found


def gentoo(version: str) -> None:
    # Imported by path (its name has a hyphen), and without leaving a
    # __pycache__ in the tree.
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(
        "gen_ebuild", HERE / "gentoo" / "gen-ebuild.py"
    )
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    written = gen.write_ebuild(version, gen.lock_at_tag(version))
    # One ebuild at a time: the overlay instructions copy the one that is here.
    for old in written.parent.glob(f"{CRATE}-*.ebuild"):
        if old != written:
            old.unlink()
            print(f"removed {old.relative_to(ROOT)}")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <version>", file=sys.stderr)
        return 2
    version = argv[1].removeprefix("v")
    if not VERSION.match(version):
        print(f"{version!r} is not a version like 0.0.15", file=sys.stderr)
        return 2

    # Every read before any write, so a release that is only half published
    # leaves the tree as it was rather than half bumped.
    source_pkgbuild = HERE / "aur" / CRATE / "PKGBUILD"
    bin_pkgbuild = HERE / "aur" / f"{CRATE}-bin" / "PKGBUILD"
    source_sums = {"sha256sums": crate_sha256(version)}
    bin_sums = {
        f"sha256sums_{arch}": tarball_sha256(version, arch)
        for arch in bin_arches(bin_pkgbuild)
    }

    bump_pkgbuild(source_pkgbuild, version, source_sums)
    bump_pkgbuild(bin_pkgbuild, version, bin_sums)
    gentoo(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
