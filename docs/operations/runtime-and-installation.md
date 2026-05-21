# Runtime and Installation

## Runtime Contract

The scanner requires the following runtime dependencies:

- Node.js `>=24.16.0`
- `pnpm` `11.1.3` or newer within the required major
- `ripgrep` (`rg`) on `PATH`

The repository itself is governed as a PNPM 11 Fortress single-project setup:

- project policy lives in `pnpm-workspace.yaml`,
- toolchain pinning lives in the root `package.json`,
- project-local `.npmrc` and `auth.ini` remain optional auth-only files and MUST stay gitignored.

## Installing ripgrep

```bash
# macOS (Homebrew)
brew install ripgrep

# Windows (Winget)
winget install BurntSushi.ripgrep.MSVC

# Ubuntu / Debian
sudo apt-get install ripgrep
```

Upstream installation reference: <https://github.com/burntsushi/ripgrep#installation>

## Installing project dependencies

```bash
pnpm install
```
