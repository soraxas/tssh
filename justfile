# Build, test, and deploy helpers for the patched tssh/tsshd fork.
# Run `just` with no args to list recipes.

# Defaults; override on the CLI: just GOOS=linux GOARCH=arm64 build
GOOS    := env_var_or_default("GOOS", "")
GOARCH  := env_var_or_default("GOARCH", "")
OUT_DIR := "bin"

# Common ldflags for slimmer binaries
LDFLAGS := "-s -w"

# default: list available recipes
default:
    @just --list

# Build both tssh and tsshd for the host (or GOOS/GOARCH if set)
build: build-tssh build-tsshd

# Build tssh into ./bin/tssh
build-tssh:
    mkdir -p {{OUT_DIR}}
    CGO_ENABLED=0 GOOS={{GOOS}} GOARCH={{GOARCH}} \
        go build -trimpath -ldflags "{{LDFLAGS}}" \
        -o {{OUT_DIR}}/tssh ./trzsz-ssh/cmd/tssh
    @echo "built {{OUT_DIR}}/tssh"

# Build tsshd into ./bin/tsshd
build-tsshd:
    mkdir -p {{OUT_DIR}}
    CGO_ENABLED=0 GOOS={{GOOS}} GOARCH={{GOARCH}} \
        go build -trimpath -ldflags "{{LDFLAGS}}" \
        -o {{OUT_DIR}}/tsshd ./tsshd/cmd/tsshd
    @echo "built {{OUT_DIR}}/tsshd"

# Build everything (sanity check that the workspace compiles)
build-all:
    go build ./trzsz-ssh/... ./tsshd/...

# Run the test suites that CI runs
test:
    go test -count=1 -timeout=180s ./tsshd/tsshd/... ./trzsz-ssh/tssh/...

# Install built binaries to ~/.local/bin (override with PREFIX=)
PREFIX := env_var_or_default("PREFIX", env_var("HOME") + "/.local/bin")
install: build
    install -d {{PREFIX}}
    install -m 0755 {{OUT_DIR}}/tssh  {{PREFIX}}/tssh
    install -m 0755 {{OUT_DIR}}/tsshd {{PREFIX}}/tsshd
    @echo "installed to {{PREFIX}}"

# Cross-build a release set (linux amd64+arm64, darwin amd64+arm64). Goreleaser
# is the source of truth for actual releases; this is for quick local checks.
release-local:
    @for os in linux darwin; do \
      for arch in amd64 arm64; do \
        echo "=== $$os/$$arch ==="; \
        just GOOS=$$os GOARCH=$$arch OUT_DIR=dist/tssh-$$os-$$arch  build-tssh; \
        just GOOS=$$os GOARCH=$$arch OUT_DIR=dist/tsshd-$$os-$$arch build-tsshd; \
      done; \
    done

# Run goreleaser snapshot (requires goreleaser >= v1.26; doesn't publish)
snapshot:
    goreleaser build --snapshot --clean

# Validate the goreleaser config
goreleaser-check:
    goreleaser check

# rsync sources to a remote host and rebuild tsshd there. Usage:
#   just deploy-tsshd main.claude.tinlai.coder
# Optional: REMOTE_PATH=/path/on/remote (defaults to ~/tsshd)
REMOTE_PATH := env_var_or_default("REMOTE_PATH", "~/tsshd")
deploy-tsshd HOST:
    rsync -Pav --delete --exclude bin/ --exclude '.git/' tsshd/ {{HOST}}:{{REMOTE_PATH}}/
    ssh {{HOST}} 'cd {{REMOTE_PATH}} && go build -trimpath -ldflags "{{LDFLAGS}}" -o bin/tsshd ./cmd/tsshd && ls -l bin/tsshd'

# Remove build artifacts
clean:
    rm -rf {{OUT_DIR}} dist

# ---------------------------------------------------------------------------
# Release helpers
# ---------------------------------------------------------------------------

# Show the latest release tag and what the next minor bump would be.
version-next:
    #!/usr/bin/env bash
    git fetch --tags --force -q 2>/dev/null || true
    latest=$(git tag --sort=-version:refname | grep -E '^v[0-9]+\.' | head -1)
    [[ -z "${latest}" ]] && latest=$(git tag --sort=-version:refname | grep -E '^v[0-9]+$' | head -1)
    [[ -z "${latest}" ]] && latest="v0.0"
    ver="${latest#v}"; major="${ver%%.*}"; minor="${ver#*.}"; minor="${minor%%.*}"
    [[ "${minor}" =~ ^[0-9]+$ ]] || minor=0
    echo "latest : ${latest}"
    echo "next   : v${major}.$((minor + 1))  (minor bump)"

# Bump the minor version, create a signed(-ish) tag, push, and publish a
# GitHub release. The release triggers publish.yml which runs goreleaser and
# uploads cross-platform binaries.
#
# Usage:
#   just release           # auto-bump minor: v0.2 → v0.3
#   just release v0.5      # exact version
#
# Requires: gh CLI authenticated, clean working tree, push access to origin.
release VERSION="":
    #!/usr/bin/env bash
    set -xeuo pipefail

    # Guard: require clean tree so the tag captures a known state.
    if [[ -n "$(git status --porcelain)" ]]; then
        echo "error: working tree is dirty — commit or stash changes first"
        exit 1
    fi

    # Fetch tags so the bump sees the current state of origin.
    git fetch --tags --force -q 2>/dev/null || true

    # Determine the tag to create.
    if [[ -n "{{VERSION}}" ]]; then
        next="{{VERSION}}"
        [[ "${next}" != v* ]] && next="v${next}"
    else
        latest=$(git tag --sort=-version:refname | grep -E '^v[0-9]+\.' | head -1)
        [[ -z "${latest}" ]] && latest=$(git tag --sort=-version:refname | grep -E '^v[0-9]+$' | head -1)
        [[ -z "${latest}" ]] && latest="v0.0"
        ver="${latest#v}"; major="${ver%%.*}"; minor="${ver#*.}"; minor="${minor%%.*}"
        [[ "${minor}" =~ ^[0-9]+$ ]] || minor=0
        next="v${major}.$((minor + 1))"
    fi

    echo "→ Creating release ${next} from $(git rev-parse --short HEAD)..."

    # Tag locally if not already tagged (idempotent — safe to retry after a
    # partial failure where the tag was created but the release was not).
    if ! git rev-parse "${next}" >/dev/null 2>&1; then
        git tag "${next}"
    fi

    # Push the tag (--no-verify skips hooks; if tag already on origin this is a no-op).
    git push origin "${next}" 2>/dev/null || true

    # Create the GitHub release. This fires publish.yml (on: release: released).
    gh release create "${next}" \
        --title "Release ${next}" \
        --generate-notes \
        --latest

    echo "✓ ${next} published."
    echo "  Watch Actions: https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/actions"
