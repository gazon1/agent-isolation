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
| user `agent` | **locked** password — not merely absent, which is not the same thing under `nullok` — a real shell, in none of `wheel`/`docker`/`kvm` |
| group `agent-dev` | narrow: the developer **and** `agent` — both are required, and `check` fails when either is missing. The collaboration seam for authorized worktrees |
| ACLs | `--x` to traverse the developer home (path access, **never** a listing); `rX` + default `rX` on configured read-only trees; `rwX` + default `rwX` on authorized worktree roots and the shared Git directory |
| sudoers | one rule, and it is the **developer's**: re-execute `/usr/bin/env` AS `agent`. The agent holds no sudo right at all |

The agent cannot write Git config or hooks: `.git/config` and `.git/hooks` are explicitly
denied, and the grant is on the common Git directory (which a linked worktree does not
carry) so commits still work.

An **adopted** account whose `passwd --status` reads `P` (usable password) or `NP` (no
password at all) is locked by `apply`; `NP` matters because a PAM stack with `nullok`
accepts it as a login. `L` is left alone. A status that cannot be read is a refusal, not
a silent skip, and `rollback` restores the recorded original — `P` and `NP` are unlocked
back, `L` is never unlocked.

### What a worktree root may contain

The grant on an authorized root is **recursive**, so every `.git` metadata directory
inside it is reached. That is safe only for the root's own repository, which is
provisioned deliberately. Two layouts are therefore refused outright, before the first
write:

| Layout | Why it is refused |
|---|---|
| a nested repository (`vendor/lib/.git`) | its `.git/config` and `.git/hooks` would be writable through the outer recursive grant. Writing `config` picks `core.hooksPath`; writing `hooks/` provides a program git runs as the developer |
| a submodule (`.git` is a file naming `../.git/modules/<name>`) | same, and the target is inside the shared store |

Authorize a root that contains no nested repositories, or remove them. Per-nested-repo
protection is not implemented; refusing is the honest answer until it is.

A **linked worktree nested inside** an authorized root is refused for the same reason.
Authorize the linked worktree itself instead — that is the supported layout, and it works:
its `.git` is a pointer file, and the invariant is that the pointer names
`<common>/worktrees/<name>` while git reports `<common>` as the common dir. `apply`
refuses a pointer that is a symlink, is owned by the agent, is group/world writable, or
resolves outside `<common>/worktrees`; it also denies ACL entries on the pointer. `check`
verifies the same four properties, so a pointer edited after provisioning to name a
repository the operator did not authorize is reported as a failure rather than certified.

### Privileged groups

`wheel`, `docker`, `kvm`, `disk`, `lxd` and `incus-admin` are refused, in the primary and
in the supplementary list, and `apply` reconciles an adopted account out of them. The
policy is **membership of a root-equivalent capability**, not a fixed distro list: `docker`
alone defeats every file permission, `disk` exposes block devices, and `lxd`/`incus-admin`
reach container-root paths. The list is deliberately the same on every distribution;
groups that exist only on some (`sudo` on Debian, `adm`, `systemd-journal`) are not
treated as privileged, because they grant log or sudo *reading* rather than an
unmediated path to root. A group whose installer makes it root-equivalent on your
distribution and is not listed here is a gap to report, not something `check` will guess.

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

### Trust boundary and privileges

`sudo ./install.sh` executes `install.sh` itself as root. The checkout, including
`install.sh`, and the build environment must be trusted. A checkout writable by an
untrusted agent can replace `install.sh` and gain root execution. Do not run it from an
untrusted checkout. This installer builds the wheel from that checkout; it does **not**
currently accept or verify a separately supplied trusted wheel artifact, and a checksum
verified by code in the same untrusted checkout is not a trust boundary.

What runs as which identity:

| Step | Runs as | Purpose |
|---|---|---|
| `uv build --wheel` | invoking user (`$SUDO_USER`) | build wheel from checkout without root build hooks |
| `uv export --frozen --format requirements-txt` | invoking user (`$SUDO_USER`) | export the committed lock as hashed requirements (artifact hashes included) |
| Path/trust checks, staging, `uv venv`, `uv pip install --require-hashes --no-deps --no-build`, symlink, `chown`/`chmod`, install rollback | root | trusted filesystem and package placement into the install prefix; dependency artifacts are verified against lock hashes |
| `ansible-galaxy collection install` | invoking user (`$SUDO_USER`) | install collections without executing artifact code as root |
| Post-install `python -I -c ...` / `ansible-playbook --version` checks | invoking user (`$SUDO_USER`) | verify installed artifact without executing it as root |

The installer resets `PATH` to a known-safe value before privileged operations and resolves
`uv` from that PATH. It refuses install roots whose existing path components are not
root-owned or are group/world-writable. For paths that do not exist yet, it validates the
nearest existing ancestor before creating directories.

**Artifact and dependency trust boundary:** the wheel is built from the trusted checkout
by the invoking user, so the checkout can influence the installed artifact. Root does
not execute build hooks or artifact verification/collection-install code during
installation, but a compromised wheel is still a compromised install. Dependency
resolution is fixed by `uv.lock`; `install.sh` exports hashed requirements from that
lock and installs dependencies with `uv pip install --require-hashes --no-deps
--no-build`, so dependency artifacts are verified against lock hashes rather than
selected only by version. Treat the checkout, including `install.sh`, and the build
environment as part of the trusted computing base.

The checkout is never linked into what root executes. Delete or modify it afterwards and
`apply` still runs the same installed code.

Verify the layout without touching the host:

```console
$ /usr/local/lib/agent-isolation/agent-isolation/bin/python -I -c 'import agent_isolation; print(agent_isolation.__file__)'
$ agent-account --help
```

### Upgrade

Re-run the installer from a newer trusted checkout:

```console
$ sudo ./install.sh
```

It replaces the venv in place and reinstalls the collections at their pinned version.
The account, its ACLs and the journal are untouched — an upgrade is not a reprovision.
Confirm with `agent-account check`.

### Install failures and manual recovery

The installer keeps the previous install in a staging backup before replacing `$LIB`.
On a normal install/upgrade failure, it restores the previous install when a backup exists.
On a first install with no backup, it removes the partial `$LIB` instead of leaving a
half-installed root-owned tree.

If rollback itself fails, the installer does **not** delete the backup or staging
directory. It prints the surviving backup path and preserved staging directory path; leave
them in place and recover manually before retrying. A typical recovery is to inspect those
paths, then move the preserved backup back to the install prefix as root:

```console
# paths are printed by install.sh on failure; inspect before moving
sudo rm -rf /usr/local/lib/agent-isolation
sudo mv <printed-backup-path> /usr/local/lib/agent-isolation
```

After manual recovery, re-run `agent-account --help` or `agent-account check` as
appropriate, then retry the install from a trusted checkout.

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

Exit codes: `0` every invariant holds **and** every security boundary was verified,
`1` at least one invariant does not hold, `2` usage or error, `3` nothing failed but at
least one security boundary could not be examined — so the host is **not** certified.

`check` needs no root, but reading another user's sudo rules does. Run unprivileged, it
reports that as `UNVERIFIED` and exits `3` rather than certifying a boundary it could not
look at; `sudo agent-account check` verifies it. Automation should treat `0` as the only
success and `3` as "ask again as root", never as "the boundary holds".

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

- **Python 3.12–3.15**, Linux with ACL support. SELinux is *queried* by `check`, not configured.
  `ansible-core` is a range rather than a pin because no single version covers that span:
  2.21.x cannot run its own entry points on Python 3.15 (`ansible-galaxy --version` and
  `ansible-playbook --version` die with `AttributeError: module 'dataclasses' has no
  attribute '_is_type'`, while `import ansible` still succeeds), and 2.22.0 needs
  Python ≥ 3.13. The committed lock resolves **both** with `python_full_version` markers,
  so one hashed requirements file installs the right one for the host — 2.22.0 on 3.13+,
  2.21.x below — and `install.sh` refuses an interpreter outside 3.12–3.15 up front
  instead of failing later inside Ansible.
- The journal in `/var/lib/agent-account` is read by shape: a state file written by the
  pre-extraction `sing` script is still understood, so a host can be adopted without
  re-provisioning.
- `--agent-group` changes what the collaboration seam is called. An existing host that
  used `sing-dev` must pass it, or `apply` will create a second group.

## Development

```console
$ python3 -m unittest discover -s tests
```

The suite runs **against `src/`**, not the installed copy, and needs no root: the seams
are objects (`Deps.accounts`, `Runner._exec`, `Deps.ansible_factory`, `Deps.execvp`)
rather than stub binaries. Tests that exercise real `setfacl`/`getfacl` create throwaway
trees and skip when the tools are absent.

`apply` needs root and is not covered by that suite; `check` is the verdict you run on a
real host.

### The installer, on a real VM

`tests/test_install_sh.py` covers `install.sh`'s logic with root operations shimmed, which
cannot answer "does `chown` really reach root, does `runuser` really drop privileges, does
the lock resolve over the network". So there is a second suite that boots Fedora Cloud
under KVM and runs the shipped script as root, with nothing stubbed in the guest:

```console
$ AGENT_ISOLATION_CONTAINER_TEST=1 python3 -m unittest tests.test_container_install -v   # ~2 min
$ AGENT_ISOLATION_VM_TEST=1        python3 -m unittest tests.test_vm_install -v          # ~5 min
```

These are a pair, and the split is not arbitrary. The **container** suite is the filter:
real root, real `chown`, real `runuser`, a real network, one throwaway container reused by
every case. The **VM** suite is the authority. A container cannot answer what the VM can —
recorded example: Fedora Cloud ships `/` at 0775 while the container image has 0755, so the
"install is impossible on a stock image" bug was invisible in the container and only the VM
caught it. Run the container one first, the VM one before release.

It is opt-in and skips without that variable, so the ordinary suite stays fast and
offline. It needs `/dev/kvm`, `qemu-system-x86_64`, `genisoimage` and `ssh`, and downloads
the Cloud image once into `~/.cache/isolation-vm/` (about 600 MB, digest-verified). Each
run boots a fresh overlay of the cached base, so the base is never mutated and the VM is
destroyed afterwards even on failure.

| Variable | Meaning |
|---|---|
| `AGENT_ISOLATION_CONTAINER_TEST` | opt in to the fast container suite |
| `AGENT_ISOLATION_VM_IMAGE` | use this local qcow2 instead of downloading |
| `AGENT_ISOLATION_VM_IMAGE_SHA256` | verify that image (required for a non-default URL) |
| `AGENT_ISOLATION_VM_CACHE` | where the download is cached |

It asserts what only a booted host can show: the tree ends up root-owned and not
group/world writable, the installed copy keeps working when the checkout is edited
afterwards, the collections land where `resolve_ansible` looks, the console script runs
for an unprivileged user, no build artifact is root-owned, `apply`/`check` succeed through
the installed tool, an upgrade leaves no staging directory behind, a failed upgrade leaves
the previous tree working, and `--uninstall` removes code without touching the account.

## Layout

```
src/agent_isolation/
  cli.py                      all of the imperative half, and the CLI
  ansible/agent-account.yml   the declarative half: group, account, home, ACLs
  ansible/requirements.yml    the pinned collection
tests/test_agent_account.py   the suite
tests/test_install_sh.py      install.sh, with root operations shimmed
tests/test_container_install.py  install.sh end to end in a container (opt-in, fast)
tests/test_vm_install.py      install.sh end to end on a booted VM (opt-in, authoritative)
tests/vm_harness.py           the cloud-init/KVM harness that suite uses
install.sh                    the root-owned install
```

The split is deliberate: Ansible makes the host match a declaration, and knows nothing
about *which* resources may be removed, which targets need a snapshot first, who wrote the
sudoers file, or what the kernel actually permits. Those stay in Python.
