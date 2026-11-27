#!/bin/sh
# install.sh — put the tool where root can safely execute it.
#
# Everything the elevated half runs is installed here, root-owned, OUTSIDE any
# project checkout:
#
#   /usr/local/lib/agent-isolation/             the tool's own venv (code + deps)
#   /usr/local/lib/agent-isolation/collections  the Ansible collections
#   /usr/local/bin/agent-account                the CLI, a symlink into that venv
#
# After this runs, `apply`/`check`/`rollback` re-execute `-m agent_isolation` from
# THIS tree. Modifying, or deleting, the source checkout afterwards changes
# nothing about what runs as root.
#
#   sudo ./install.sh              install or upgrade in place
#   sudo ./install.sh --uninstall  remove installed code (the account stays)
#
# The account, its ACLs and its journal are NOT touched by either: those belong to
# `agent-account apply` / `agent-account rollback`.

set -eu

PREFIX=${PREFIX:-/usr/local}
LIB="$PREFIX/lib/agent-isolation"
BIN="$PREFIX/bin/agent-account"
SOURCE=$(cd "$(dirname "$0")" && pwd)
UNINSTALL=no

for arg in "$@"; do
    case "$arg" in
        --uninstall) UNINSTALL=yes ;;
        -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "install.sh: unknown argument: $arg" >&2; exit 2 ;;
    esac
done

# The privileged half runs from here, so nothing may be owned by a non-root account
# or be writable by one. Checked, not merely created: an attacker who pre-creates
# the directory wins otherwise.
assert_trusted() {
    for path in "$@"; do
        [ -e "$path" ] || continue
        # A SYMLINK is followed: `stat` on a link reports 0777 on Linux whatever it
        # points at, so checking the link itself refused every uninstall of our own
        # `/usr/local/bin/agent-account`. What matters is the target, and whether
        # the link sits in a directory somebody else can write (checked above).
        if [ -L "$path" ]; then
            owner=$(stat -L -c %u "$path")
            perms=$(stat -L -c "%a" "$path")
            if [ "$owner" -ne 0 ] || [ $((0$perms & 022)) -ne 0 ]; then
                echo "install.sh: $path -> $(readlink -f "$path") is not root-owned and read-only" >&2
                exit 1
            fi
            continue
        fi
        owner=$(stat -c %u "$path")
        if [ "$owner" -ne 0 ]; then
            echo "install.sh: $path is owned by uid $owner, not root — refusing to use it" >&2
            exit 1
        fi
        perms=$(stat -c "%a" "$path")
        # Group or world write on a directory is a path for a non-root user to
        # replace the code root will execute.
        if [ $((0$perms & 022)) -ne 0 ]; then
            echo "install.sh: $path is group- or world-writable (mode $perms)" >&2
            exit 1
        fi
    done
}

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: must run as root (try: sudo $0)" >&2
    exit 1
fi

if [ "$UNINSTALL" = yes ]; then
    assert_trusted "$LIB" "$BIN"
    rm -f "$BIN"
    rm -rf "$LIB"
    echo "Removed $LIB and $BIN."
    echo "The agent account is untouched; remove it with: agent-account rollback"
    exit 0
fi

# `uv` is a TOOL that runs as root here, so it is held to the same rule as the code:
# it must be root-owned and not writable by anyone else. A developer's mise shim is
# exactly what this refuses — measured on Fedora, `command -v uv` answered
# /home/max/.local/share/mise/shims/uv, a mode-0777 launcher owned by uid 1000.
# Running that as root is the vulnerability the install exists to prevent.
UV=$(command -v uv 2>/dev/null || true)
if [ -z "$UV" ]; then
    echo "install.sh: uv is required (https://docs.astral.sh/uv/, or: dnf install uv)" >&2
    exit 1
fi
assert_trusted "$UV"

# Refuse BEFORE creating anything: a world-writable parent is not a trusted root.
# $LIB itself is checked too — an existing directory owned by somebody else, or
# writable by them, is a place `uv` would run as root inside.
assert_trusted "$PREFIX/lib" "$PREFIX/bin" "$LIB"
# Created 0755 and root-owned by this root-owned call: the mode is set explicitly
# because the caller's umask must not be able to loosen it.
install -d -m 0755 -o root -g root "$LIB"

# `uv tool install` builds a wheel and unpacks it into a venv under this directory,
# so the installed tree is a COPY: the checkout is not linked into it, and
# modifying or removing the checkout afterwards changes nothing.
echo "Installing the tool into $LIB ..."
# `--python /usr/bin/python3` and not `3.12`: naming a version lets uv resolve it to
# a download under `~/.local/share/uv/python`, owned by the calling user. The
# interpreter root executes has to come from root's own system.
UV_TOOL_DIR="$LIB" UV_TOOL_BIN_DIR="$LIB/bin-dir" "$UV" tool install \
    --python /usr/bin/python3 \
    --force \
    "$SOURCE"

ln -sfn "$LIB/bin-dir/agent-account" "$BIN"

# The collections are data the playbook imports. They live beside the code, so the
# elevated playbook never reads one from a user home or a checkout.
echo "Installing Ansible collections into $LIB/collections ..."
"$LIB/agent-isolation/bin/ansible-galaxy" collection install \
    -r "$SOURCE/src/agent_isolation/ansible/requirements.yml" \
    -p "$LIB/collections" \
    --force

# Verify the INSTALL, not the checkout: this is what root will execute.
"$LIB/agent-isolation/bin/python" -I -c 'import agent_isolation; print("code:", agent_isolation.__file__)'
"$LIB/agent-isolation/bin/ansible-playbook" --version >/dev/null

chown -R root:root "$LIB"
chmod -R go-w "$LIB"

echo
echo "Installed:"
echo "  code        $("$LIB/agent-isolation/bin/python" -I -c 'import agent_isolation, os; print(os.path.dirname(agent_isolation.__file__))')"
echo "  collections $LIB/collections"
echo "  command     $BIN"
echo
echo "Next: $BIN apply --dry-run <worktree...>"
