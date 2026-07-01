#!/usr/bin/env bash
# Build a Debian package for HopTerm.
#
#   packaging/make-deb.sh              # release build + package
#   REV=2 packaging/make-deb.sh        # bump the Debian revision
#   SKIP_BUILD=1 packaging/make-deb.sh # reuse an existing target/release/hopterm
#   ARCH=arm64 packaging/make-deb.sh   # override the target architecture
#
# Output: dist/hopterm_<version>-<rev>_<arch>.deb
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"   # cargo workspace root (…/rustssh)
cd "$root"

# ---- metadata -------------------------------------------------------------
VER="$(sed -n '/^\[workspace\.package\]/,/^\[/p' Cargo.toml | grep -m1 '^version' | sed 's/.*"\(.*\)".*/\1/')"
REV="${REV:-1}"
ARCH="${ARCH:-$(dpkg --print-architecture)}"
MAINTAINER="${MAINTAINER:-Yaroslav Smirnov <yarsmirnov59@gmail.com>}"
# webkit pulls in gtk/glib/jsc transitively; the alternative covers Ubuntu's t64 rename.
DEPENDS="${DEPENDS:-libwebkit2gtk-4.1-0, libgtk-3-0 | libgtk-3-0t64, libc6}"

bin="target/release/hopterm"
[ "${SKIP_BUILD:-0}" = "1" ] || cargo build --release -p hopterm-ui
[ -f "$bin" ] || { echo "error: $bin not found" >&2; exit 1; }

# ---- assemble the package tree -------------------------------------------
name="hopterm_${VER}-${REV}_${ARCH}"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
pkg="$stage/$name"
mkdir -p "$pkg/DEBIAN"

install -Dm755 "$bin" "$pkg/usr/bin/hopterm"
strip --strip-unneeded "$pkg/usr/bin/hopterm" 2>/dev/null || true
install -Dm644 "$here/hopterm.desktop" "$pkg/usr/share/applications/hopterm.desktop"
install -Dm644 "$here/hopterm.svg" "$pkg/usr/share/icons/hicolor/scalable/apps/hopterm.svg"
[ -f "$here/hopterm.png" ] && install -Dm644 "$here/hopterm.png" "$pkg/usr/share/icons/hicolor/256x256/apps/hopterm.png"

install -Dm644 /dev/stdin "$pkg/usr/share/doc/hopterm/copyright" <<EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: HopTerm

Files: *
Copyright: 2026 $MAINTAINER
License: MIT
EOF

isize="$(du -k -s "$pkg/usr" | cut -f1)"

cat > "$pkg/DEBIAN/control" <<EOF
Package: hopterm
Version: ${VER}-${REV}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: ${DEPENDS}
Maintainer: ${MAINTAINER}
Installed-Size: ${isize}
Description: HopTerm — multi-hop SSH terminal manager
 Cross-platform GUI SSH client: unlimited jump-host chains, an interactive
 terminal, SFTP transfer over the same chain, a quick-command builder and
 archive-on-the-fly downloads. GUI rendered with a system webview.
EOF

# ---- maintainer scripts: refresh icon/desktop caches ----------------------
cat > "$pkg/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor 2>/dev/null || true
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications 2>/dev/null || true
exit 0
EOF
cat > "$pkg/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor 2>/dev/null || true
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications 2>/dev/null || true
fi
exit 0
EOF
chmod 755 "$pkg/DEBIAN/postinst" "$pkg/DEBIAN/postrm"

# ---- build ----------------------------------------------------------------
mkdir -p "$root/dist"
out="$root/dist/${name}.deb"
dpkg-deb --root-owner-group --build "$pkg" "$out" >/dev/null
echo "built: $out"
dpkg-deb --info "$out" | sed -n '/Package:/,/Description:/p' | sed 's/^/  /'
