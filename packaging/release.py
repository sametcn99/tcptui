"""Build release assets from the same tested tcptui and tcpvcon binaries."""

import argparse
import hashlib
import json
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]
REPO = "https://github.com/sametcn99/tcptui"
DOWNLOAD = f"{REPO}/releases/download/v{VERSION}"
TARGETS = (
    ("windows", "x86_64"),
    ("linux", "x86_64"),
    ("linux", "aarch64"),
    ("macos", "x86_64"),
    ("macos", "aarch64"),
)


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def archive_name(platform, arch):
    extension = "zip" if platform == "windows" else "tar.gz"
    return f"tcptui-v{VERSION}-{platform}-{arch}.{extension}"


def binary_files(directory, windows=False):
    extension = ".exe" if windows else ""
    return [directory / f"{name}{extension}" for name in ("tcptui", "tcpvcon")]


def archive(platform, arch, binaries, out):
    if (platform, arch) not in TARGETS:
        raise ValueError(f"unsupported release target {platform}/{arch}")
    windows = platform == "windows"
    output = out / archive_name(platform, arch)
    files = binary_files(binaries, windows) + [ROOT / "README.md", ROOT / "LICENSE"]
    if windows:
        files += [binaries / name for name in ("frame-dark.txt", "frame-wide.txt")]
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zipped:
            for path in files:
                zipped.write(path, path.name)
    else:
        with tarfile.open(output, "w:gz") as zipped:
            for path in files:
                zipped.add(path, arcname=path.name)


def deb(arch, binaries, out):
    deb_arch = {"x86_64": "amd64", "aarch64": "arm64"}[arch]
    with tempfile.TemporaryDirectory() as temporary:
        stage = Path(temporary) / "tcptui"
        for path in binary_files(binaries):
            install(path, stage / "usr/bin" / path.name, 0o755)
        install(ROOT / "LICENSE", stage / "usr/share/doc/tcptui/copyright")
        install(ROOT / "README.md", stage / "usr/share/doc/tcptui/README.md")
        metadata = stage / "DEBIAN"
        metadata.mkdir()
        (metadata / "control").write_text(
            f"""Package: tcptui
Version: {VERSION}
Architecture: {deb_arch}
Maintainer: sametcn99 <sametcn99@users.noreply.github.com>
Section: net
Priority: optional
Depends: libc6 (>= 2.35), libgcc-s1, libssl3 | libssl3t64, ca-certificates
Homepage: {REPO}
Description: Terminal TCP and UDP endpoint monitor
 Includes the interactive tcptui and scriptable tcpvcon commands.
""",
            encoding="utf-8",
        )
        subprocess.run(
            ["dpkg-deb", "-Zxz", "--root-owner-group", "--build", stage, out / f"tcptui_{VERSION}_{deb_arch}.deb"],
            check=True,
        )


def rpm(arch, binaries, out):
    with tempfile.TemporaryDirectory() as temporary:
        topdir = Path(temporary) / "rpmbuild"
        sources = topdir / "SOURCES"
        sources.mkdir(parents=True)
        for source in binary_files(binaries) + [ROOT / "LICENSE", ROOT / "README.md"]:
            shutil.copy2(source, sources / source.name)
        spec = topdir / "tcptui.spec"
        spec.write_text(
            f"""%global debug_package %{{nil}}
%global _build_id_links none
Name: tcptui
Version: {VERSION}
Release: 1
Summary: Terminal TCP and UDP endpoint monitor
License: MIT
Requires: ca-certificates
URL: {REPO}

%description
Interactive tcptui and scriptable tcpvcon commands for inspecting sockets.

%install
install -Dm755 %{{_sourcedir}}/tcptui %{{buildroot}}%{{_bindir}}/tcptui
install -Dm755 %{{_sourcedir}}/tcpvcon %{{buildroot}}%{{_bindir}}/tcpvcon
install -Dm644 %{{_sourcedir}}/LICENSE %{{buildroot}}%{{_licensedir}}/tcptui/LICENSE
install -Dm644 %{{_sourcedir}}/README.md %{{buildroot}}%{{_docdir}}/tcptui/README.md

%files
%{{_bindir}}/tcptui
%{{_bindir}}/tcpvcon
%license %{{_licensedir}}/tcptui/LICENSE
%doc %{{_docdir}}/tcptui/README.md
""",
            encoding="utf-8",
        )
        subprocess.run(
            ["rpmbuild", "--define", f"_topdir {topdir}", "--target", arch, "-bb", spec],
            check=True,
        )
        name = f"tcptui-{VERSION}-1.{arch}.rpm"
        shutil.copy2(topdir / "RPMS" / arch / name, out / name)


def install(source, target, mode=0o644):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)


def formula(assets, out, local_arch=None):
    arch_map = (("aarch64", "on_arm"), ("x86_64", "on_intel"))
    blocks = []
    for arch, selector in arch_map:
        if local_arch and arch != local_arch:
            continue
        asset = assets / archive_name("macos", arch)
        url = asset.as_uri() if local_arch else f"{DOWNLOAD}/{asset.name}"
        blocks.append(f'  {selector} do\n    url "{url}"\n    sha256 "{sha256(asset)}"\n  end\n')
    (out / "tcptui.rb").write_text(
        f'''class Tcptui < Formula
  desc "Terminal TCP and UDP endpoint monitor"
  homepage "{REPO}"
  version "{VERSION}"
  license "MIT"

  depends_on macos: :sequoia

''' + "\n".join(blocks) + f'''
  def install
    bin.install "tcptui", "tcpvcon"
  end

  test do
    assert_match "tcptui {VERSION}", shell_output("#{{bin}}/tcptui --version")
    assert_match "tcpvcon {VERSION}", shell_output("#{{bin}}/tcpvcon --version")
  end
end
''',
        encoding="utf-8",
    )


def arch_recipe(assets, out):
    asset = assets / archive_name("linux", "x86_64")
    checksum = sha256(asset)
    url = f"{DOWNLOAD}/{asset.name}"
    (out / "PKGBUILD").write_text(
        f"""# Maintainer: sametcn99 <sametcn99@users.noreply.github.com>
pkgname=tcptui-bin
pkgver={VERSION}
pkgrel=1
pkgdesc='Terminal TCP and UDP endpoint monitor'
arch=('x86_64')
url='{REPO}'
license=('MIT')
depends=('glibc' 'gcc-libs' 'openssl' 'ca-certificates')
provides=('tcptui')
conflicts=('tcptui')
source=('{url}')
sha256sums=('{checksum}')

package() {{
  install -Dm755 "$srcdir/tcptui" "$pkgdir/usr/bin/tcptui"
  install -Dm755 "$srcdir/tcpvcon" "$pkgdir/usr/bin/tcpvcon"
  install -Dm644 "$srcdir/LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 "$srcdir/README.md" "$pkgdir/usr/share/doc/$pkgname/README.md"
}}
""",
        encoding="utf-8",
    )
    (out / ".SRCINFO").write_text(
        f"""pkgbase = tcptui-bin
\tpkgdesc = Terminal TCP and UDP endpoint monitor
\tpkgver = {VERSION}
\tpkgrel = 1
\turl = {REPO}
\tarch = x86_64
\tlicense = MIT
\tdepends = glibc
\tdepends = gcc-libs
\tdepends = openssl
\tdepends = ca-certificates
\tprovides = tcptui
\tconflicts = tcptui
\tsource = {url}
\tsha256sums = {checksum}

pkgname = tcptui-bin
""",
        encoding="utf-8",
    )


def finalize(assets):
    expected = [archive_name(platform, arch) for platform, arch in TARGETS]
    expected += [f"tcptui_{VERSION}_{arch}.deb" for arch in ("amd64", "arm64")]
    expected += [f"tcptui-{VERSION}-1.{arch}.rpm" for arch in ("x86_64", "aarch64")]
    for name in expected:
        if not (assets / name).is_file() or (assets / name).stat().st_size == 0:
            raise FileNotFoundError(f"missing or empty release asset: {name}")

    manifest = json.loads((ROOT / "packaging/scoop/tcptui.json").read_text(encoding="utf-8"))
    manifest["version"] = VERSION
    windows = archive_name("windows", "x86_64")
    manifest["architecture"]["64bit"].update(url=f"{DOWNLOAD}/{windows}", hash=sha256(assets / windows))
    (assets / "scoop-tcptui.json").write_text(json.dumps(manifest, indent=4) + "\n", encoding="utf-8")
    formula(assets, assets)
    with tempfile.TemporaryDirectory() as temporary:
        recipes = Path(temporary)
        arch_recipe(assets, recipes)
        with tarfile.open(assets / "tcptui-bin-aur.tar.gz", "w:gz") as zipped:
            for name in ("PKGBUILD", ".SRCINFO"):
                zipped.add(recipes / name, arcname=name)
    checksum = assets / "sha256sums.txt"
    checksums = [f"{sha256(path)}  {path.name}\n" for path in sorted(assets.iterdir()) if path.is_file() and path != checksum]
    checksum.write_text("".join(checksums), encoding="ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="Require the specified tag to match Cargo.toml")
    subcommands = parser.add_subparsers(dest="command", required=True)

    for name in ("archive", "deb", "rpm"):
        subcommand = subcommands.add_parser(name)
        if name == "archive":
            subcommand.add_argument("platform", choices=("windows", "linux", "macos"))
        subcommand.add_argument("arch", choices=("x86_64", "aarch64"))
        subcommand.add_argument("binaries", type=Path)
        subcommand.add_argument("out", type=Path)

    for name in ("formula", "arch-recipe"):
        subcommand = subcommands.add_parser(name)
        subcommand.add_argument("assets", type=Path)
        subcommand.add_argument("out", type=Path)
        if name == "formula":
            subcommand.add_argument("--local-arch", choices=("x86_64", "aarch64"))

    subcommands.add_parser("finalize").add_argument("assets", type=Path)
    args = parser.parse_args()
    if args.tag and args.tag != f"v{VERSION}":
        parser.error(f"tag {args.tag} does not match Cargo.toml version {VERSION}")
    if hasattr(args, "out"):
        args.out.mkdir(parents=True, exist_ok=True)
    match args.command:
        case "archive":
            archive(args.platform, args.arch, args.binaries, args.out)
        case "deb":
            deb(args.arch, args.binaries, args.out)
        case "rpm":
            rpm(args.arch, args.binaries, args.out)
        case "formula":
            formula(args.assets.resolve(), args.out, args.local_arch)
        case "arch-recipe":
            arch_recipe(args.assets, args.out)
        case "finalize":
            finalize(args.assets)


if __name__ == "__main__":
    main()
