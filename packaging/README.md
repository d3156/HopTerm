# Packaging

Build a `.deb` for HopTerm in one command:

```sh
packaging/make-deb.sh
```

Output: `dist/hopterm_<version>-<rev>_<arch>.deb`
(version is read from `[workspace.package]` in `Cargo.toml`).

## Options (env vars)

| Var | Default | Purpose |
|-----|---------|---------|
| `REV` | `1` | Debian revision — bump on re-release of the same version |
| `SKIP_BUILD` | `0` | `1` = reuse existing `target/release/hopterm`, don't rebuild |
| `ARCH` | host arch | target architecture string |
| `MAINTAINER` | Yaroslav Smirnov … | `Name <email>` |
| `DEPENDS` | webkit/gtk/libc | override the `Depends:` line |

Examples:

```sh
REV=2 packaging/make-deb.sh          # rebuild + bump revision
SKIP_BUILD=1 packaging/make-deb.sh   # package the current binary as-is
```

## Contents of the package

- `/usr/bin/hopterm` — the stripped release binary (web assets embedded)
- `/usr/share/applications/hopterm.desktop` — menu launcher
- `/usr/share/icons/hicolor/{scalable,256x256}/apps/hopterm.*` — icon
- `postinst`/`postrm` refresh the icon + desktop caches

Sources (`hopterm.desktop`, `hopterm.svg`, `hopterm.png`) live in this folder,
so the build is self-contained.

## Install / remove

```sh
sudo apt install ./dist/hopterm_0.1.0-1_amd64.deb   # resolves deps
sudo apt remove hopterm
```
