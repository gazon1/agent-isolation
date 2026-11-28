# agent-isolation

The hardened host account manager: a **dedicated unprivileged Unix account** that coding
agents run as, with the ACL layout, sudoers rule, journal and rollback that make it
usable.

An agent that runs as the interactive developer owns everything the developer owns — and
`docker` membership is root-equivalent, so a file permission means nothing. This tool
creates the "somebody else" the rest of an isolation design starts from.

```console
$ agent-account apply --dry-run ~/work/wt1     # the plan; needs no root
$ sudo agent-account apply ~/work/wt1          # one password prompt; creates it
$ agent-account check ~/work/wt1               # PASS/FAIL on every invariant
$ agent-account run -- git status              # a command AS the agent
$ sudo agent-account rollback                  # undo what apply wrote
```

## What it creates, and nothing else

| Resource | Detail |
|---|---|
| user `agent` | no password (no login), a real shell, in none of `wheel`/`docker`/`kvm` |
| group `agent-dev` | narrow: the developer and `agent`. The collaboration seam for authorized worktrees |
| ACLs | `--x` to traverse the developer home (path access, **never** a listing); `rX` + default `rX` on configured read-only trees; `rwX` + default `rwX` on authorized worktree roots and the shared Git directory |
| sudoers | one rule, and it is the **developer's**: re-execute `/usr/bin/env` AS `agent`. The agent holds no sudo right at all |

The agent cannot write Git config or hooks: `.git/config` and `.git/hooks` are explicitly
denied, and the grant is on the common Git directory (which a linked worktree does not
carry) so commits still work.

## Install

Prerequisites: a Linux host with ACL support, `sudo`, and [`uv`](https://docs.astral.sh/uv/).

```console
$ sudo ./install.sh
```

That installs, **root-owned and outside any project checkout**:

| Path | Contents |
|---|---|
| `/usr/local/lib/agent-isolation/agent-isolation/` | the tool's own venv: code, `click`, `pydantic`, `ansible-core` |
| `/usr/local/lib/agent-isolation/collections/` | the `ansible.posix` collection the playbook imports |
| `/usr/local/bin/agent-account` | the CLI, a symlink into that venv |

The install is a **copy**, and it is built **without root**. `install.sh` builds the
wheel as the invoking user, then root installs that prebuilt artifact with `--no-build`.
A malicious build backend in the checkout therefore never executes with root privileges —
measured: a hatch hook planted in `pyproject.toml` runs as the calling user, never as root.

Post-install verification also runs as the invoking user, not root, so code from the
installed artifact is not executed with root privileges during installation.

The checkout is never linked into what root executes. Delete or modify it afterwards and
`apply` still runs the same installed code.

**Artifact trust boundary:** the wheel is built from the checkout by the invoking user, so
the checkout can influence the installed artifact. Root does not execute that artifact
during installation, but a compromised wheel is still a compromised install. Install from a
trusted, independently verified wheel, or treat the checkout and build environment as part
of the trusted computing base.

Verify the layout without touching the host:

```console
$ /usr/local/lib/agent-isolation/agent-isolation/bin/python -I -c 'import agent_isolation; print(agent_isolation.__file__)'
$ agent-account --help
```

### Upgrade

Re-run the installer from a newer checkout:

```console
$ sudo ./install.sh
```

It replaces the venv in place and reinstalls the collections at their pinned version.
The account, its ACLs and the journal are untouched — an upgrade is not a reprovision.
Confirm with `agent-account check`.

### Rollback of the install (not the account)

```console
$ sudo ./install.sh --uninstall
```

Removes the installed code and the symlink. The account survives; remove it with
`agent-account rollback` **before** uninstalling if that is the intent.

### Rollback of the account

```console
$ sudo agent-account rollback --dry-run   # what it will undo
$ sudo agent-account rollback
```

Rollback removes only what `apply` **created**, from the journal it left in
`/var/lib/agent-account`. An `agent` account or group that predated this tool is
**adopted**, not deleted. ACLs are restored from the `getfacl` dump taken before each
write, so a hand-edited entry comes back byte for byte.

## Supported interface

The CLI is the contract. Everything on this list is stable; anything else is internal.

```
agent-account [OPTIONS] apply    [ROOTS...]
agent-account [OPTIONS] check    [ROOTS...]
agent-account [OPTIONS] run -- COMMAND [ARGS...]
agent-account [OPTIONS] rollback [ROOTS...]
```

| Option | Meaning | Default |
|---|---|---|
| `--dev USER` | the interactive developer | `$SUDO_USER`, then the caller |
| `--agent-user NAME` | the account to create or adopt | `agent` |
| `--agent-group NAME` | the collaboration group | `agent-dev` |
| `--sdk-dir REL` | a read-only SDK, relative to `$HOME` | none (skipped) |
| `--toolchain REL` | a read-only toolchain directory, repeatable | none (skipped) |
| `--dry-run` | print the plan, change nothing | off |
| `--allow-in-home` | accept a root inside `$HOME` | off |

Exit codes: `0` every invariant holds, `1` at least one does not, `2` usage or error.

There is deliberately **no** option to point the tool at another Ansible, another
collection directory, or a `PYTHONPATH`. An Ansible collection is Python code, and the
privileged half resolves both from its own installation: `--ansible-collections` (or an
`ANSIBLE_COLLECTIONS_PATH` in the environment) would otherwise be a way to make root
import code from a writable directory.

**Nothing host-specific is assumed.** The Singularity consumer passes
`--agent-group sing-dev --sdk-dir Android/Sdk --toolchain .local/share/mise
--toolchain .local/bin`; a plain host passes none of them and gets the account, the
worktree grants and the sudoers rule alone.

### Compatibility

- **Python ≥ 3.12** (the pinned `ansible-core` requires it), Linux with ACL support. SELinux is *queried* by `check`, not configured.
- The journal in `/var/lib/agent-account` is read by shape: a state file written by the
  pre-extraction `sing` script is still understood, so a host can be adopted without
  re-provisioning.
- `--agent-group` changes what the collaboration seam is called. An existing host that
  used `sing-dev` must pass it, or `apply` will create a second group.

## Development

```console
$ python3 -m unittest discover -s tests -p 'test_agent_account.py'
```

The suite runs **against `src/`**, not the installed copy, and needs no root: the seams
are objects (`Deps.accounts`, `Runner._exec`, `Deps.ansible_factory`, `Deps.execvp`)
rather than stub binaries. Tests that exercise real `setfacl`/`getfacl` create throwaway
trees and skip when the tools are absent.

`apply` needs root and is not covered by the suite; `check` is the verdict you run on a
real host.

## Layout

```
src/agent_isolation/
  cli.py                      all of the imperative half, and the CLI
  ansible/agent-account.yml   the declarative half: group, account, home, ACLs
  ansible/requirements.yml    the pinned collection
tests/test_agent_account.py   the suite
install.sh                    the root-owned install
```

The split is deliberate: Ansible makes the host match a declaration, and knows nothing
about *which* resources may be removed, which targets need a snapshot first, who wrote the
sudoers file, or what the kernel actually permits. Those stay in Python.
