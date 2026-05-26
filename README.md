# tssh / tsshd — patched fork

A patched build of [trzsz-ssh](https://github.com/trzsz/trzsz-ssh) (`tssh`)
and [tsshd](https://github.com/trzsz/tsshd) with two additions:

- **`tssh --punch`** — STUN-based UDP hole punching so `tssh --udp HOSTNAME`
  works when `tsshd` is behind NAT. The client STUNs its socket, passes its
  public endpoint to `tsshd --punch ...`, the server STUNs its own socket and
  begins sending punch packets toward the client. Both peers reuse the same
  socket the whole time so the NAT mapping stays valid into the live UDP
  transport. Works for cone NATs (full-cone, restricted, port-restricted).
  Symmetric NATs cannot be punched through and will still fail.
- **PTY-fd leak fix in `tsshd`** — `tsshd` daemonized incompletely on POSIX:
  the forked child inherited the parent SSH session's stdin/stderr (PTY slave
  fds). When the parent exited, the PTY master never saw EOF, so
  `session.Wait()` on the client side blocked forever. Vanilla OpenSSH usually
  tolerated this, but stricter SSH server proxies (e.g. Coder's) did not. The
  child now closes its inherited stdin/stderr after the parent has finished
  reading the handshake.

The two subdirectories `trzsz-ssh/` and `tsshd/` are tracked with
[`git subrepo`](https://github.com/ingydotnet/git-subrepo) and pin specific
upstream commits. A repo-root `go.work` wires them together so the patched
tssh builds against the patched tsshd.

## Install

Pre-built binaries are attached to each GitHub release. Each `tssh_VERSION_OS_ARCH`
archive contains **both** `tssh` and `tsshd` so installing one gets you the matching
pair.

```sh
# example: Linux x86_64
TAG=$(curl -s https://api.github.com/repos/soraxas/tssh/releases/latest | grep tag_name | cut -d'"' -f4)
curl -L -o tssh.tar.gz "https://github.com/soraxas/tssh/releases/download/${TAG}/tssh_${TAG#v}_linux_x86_64.tar.gz"
tar -xzf tssh.tar.gz
sudo install -m 0755 tssh_*/{tssh,tsshd} /usr/local/bin/
```

### mise

```sh
mise use ubi:soraxas/tssh
```

The combined archive layout means `mise` pulls one asset per platform and finds
both binaries inside. To pin a version:

```toml
# mise.toml
[tools]
"ubi:soraxas/tssh" = "0.1.0"
```

### Linux packages

Per-binary `.deb` and `.rpm` packages are also attached to each release for
people who only want one of the two:

```sh
# tssh only
curl -LO "https://github.com/soraxas/tssh/releases/download/${TAG}/tssh_${TAG#v}_linux_x86_64.deb"
sudo dpkg -i tssh_${TAG#v}_linux_x86_64.deb
```

The latest dev build of `master` is also published under the `dev` release
tag and updated on every push.

## Build from source

This is a multi-module Go workspace. The repo-root `go.work` is required —
without it, the patched `tssh` resolves to the published `tsshd` module
(without `--punch`) and fails to compile.

If you have [`just`](https://github.com/casey/just):

```sh
just build              # → ./bin/tssh and ./bin/tsshd
just test               # run the patched test suites
just install            # install to ~/.local/bin (override with PREFIX=)
just deploy-tsshd HOST  # rsync sources to HOST and rebuild tsshd there
just --list             # see all recipes
```

Or plain `go`:

```sh
git clone https://github.com/soraxas/tssh
cd tssh
go build -o bin/tssh  ./trzsz-ssh/cmd/tssh
go build -o bin/tsshd ./tsshd/cmd/tsshd
go test ./trzsz-ssh/tssh/... ./tsshd/tsshd/...
```

## Usage

Once installed on both ends, hole punching is opt-in:

```sh
# explicit one-off
tssh --udp HOST --punch
```

Or set it as the default for a host in `~/.ssh/config`:

```
Host my-nat-host
    ExOption UdpMode=yes
    ExOption UdpHolePunch=yes
```

Then plain `tssh my-nat-host` performs hole-punched UDP automatically.

Override the STUN server with `--stun-host` / `--stun-port` flags on `tsshd`,
or `ExOption UdpStunHost=...` / `UdpStunPort=...` on `tssh`. Default is
`stun.l.google.com:19302`.

Hole punching is skipped (with a warning) when a `ProxyJump` is configured
or when `UdpProxyMode=tcp` is set, since both bypass the direct UDP path.

## Upstream

- <https://github.com/trzsz/trzsz-ssh>
- <https://github.com/trzsz/tsshd>

Pull both subrepos forward with `git subrepo pull trzsz-ssh tsshd`.
