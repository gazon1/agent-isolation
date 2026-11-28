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

# A KNOWN-SAFE PATH, before anything else runs.
#
# Measured: `sudo env PATH=/tmp/hijack:$PATH ./install.sh` executed a hostile `stat`
# from that directory, and `assert_trusted` performs its checks with `stat`,
# `readlink` and `dirname`. A trust check whose tools come from the caller's PATH is
# not a trust check. sudo's `secure_path` would usually cover this, but the script
# must not depend on the caller's sudoers.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH

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
#
# EVERY component of a path is checked, not just the final entry. Measured: a
# symlink `/tmp/writable-dir/uv -> /usr/bin/uv` was ACCEPTED, because the target is
# root-owned and read-only — while the world-writable directory holding the link
# lets any user re-point it between this check and the `exec` below. Same for a
# custom PREFIX: `/tmp/prefix/lib` can pass while `/tmp/prefix` itself is writable.
#
# `readlink -f` canonicalises first, so a path is judged where it really lives —
# but canonicalising alone is not enough, and that is the subtle part: for
# `/tmp/writable-dir/uv -> /usr/bin/uv` it answers `/usr/bin/uv`, whose components
# are all root-owned, while the DIRECTORY HOLDING THE LINK stays world-writable and
# can re-point it at any moment between this check and the `exec`. So both the path
# AS GIVEN and its canonical target are walked.
#
# This is check-then-use, and it is only as safe as the components being unwritable
# by anyone but root — which is exactly what the walk establishes.
assert_trusted() {
    _walk() {
        check=$1
        while :; do
            # `-L`: a DIRECTORY that is a symlink (/usr/sbin -> bin) reports 0777
            # on the link itself, which would refuse every normal Fedora install —
            # measured. The target is what the exec will traverse.
            owner=$(stat -L -c %u "$check")
            perms=$(stat -L -c "%a" "$check")
            if [ "$owner" -ne 0 ]; then
                echo "install.sh: $check is owned by uid $owner, not root — refusing to use it" >&2
                exit 1
            fi
            # Group or world write is a path for a non-root user to replace the code
            # root will execute. The sticky bit does not help: it stops deletion of
            # entries the writer does not own, not re-pointing one it does.
            if [ $((0$perms & 022)) -ne 0 ]; then
                echo "install.sh: $check is group- or world-writable (mode $perms)" >&2
                exit 1
            fi
            [ "$check" = "/" ] && break
            check=$(dirname -- "$check")
        done
    }
    for path in "$@"; do
        case $path in /*) abs=$path ;; *) abs=$PWD/$path ;; esac
        if [ -e "$abs" ]; then
            # The path as given: catches a writable directory holding the entry.
            _walk "$abs"
            # Its real location: catches a writable ancestor behind a symlink.
            canonical=$(readlink -f -- "$abs")
            if [ -z "$canonical" ]; then
                echo "install.sh: cannot canonicalise $abs" >&2
                exit 1
            fi
            _walk "$canonical"
        else
            # The path does not exist yet; the nearest existing ancestor is where
            # an attacker controls what gets created. Validate that ancestor and
            # every existing component above it before any directory is made.
            ancestor=$abs
            while [ ! -e "$ancestor" ]; do
                parent=$(dirname -- "$ancestor")
                [ "$parent" = "$ancestor" ] && break
                ancestor=$parent
            done
            if [ ! -e "$ancestor" ]; then
                echo "install.sh: no existing ancestor for $abs" >&2
                exit 1
            fi
            _walk "$ancestor"
            canonical=$(readlink -f -- "$ancestor")
            if [ -z "$canonical" ]; then
                echo "install.sh: cannot canonicalise $ancestor" >&2
                exit 1
            fi
            _walk "$canonical"
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
# Resolved against the safe PATH set at the top, so this cannot be a caller's
# shim. `assert_trusted` then confirms the whole path is root-owned.
UV=$(command -v uv 2>/dev/null || true)
if [ -z "$UV" ]; then
    echo "install.sh: uv is required on the system PATH (dnf install uv)" >&2
    exit 1
fi
assert_trusted "$UV"

# Refuse BEFORE creating anything: a world-writable parent is not a trusted root.
# $LIB itself is checked too — an existing directory owned by somebody else, or
# writable by them, is a place `uv` would run as root inside.
assert_trusted "$PREFIX/lib" "$PREFIX/bin" "$LIB"
# -- build as the INVOKING user, install as root -------------------------------
#
# Measured: `uv tool install .` runs the project's build backend, and a malicious
# hook in the checkout wrote a file as the invoking user. Under `sudo` that hook
# would run as ROOT — the escalation this install exists to prevent.
#
# So the build is done by the unprivileged caller and root only ever installs a
# PREBUILT WHEEL with `--no-build`: no build backend, no setup.py, no hatch hook
# from the checkout is executed with root privileges.
#
# Trust boundary: `sudo ./install.sh` executes this script as root, so the
# checkout (including this file) and the build environment must be trusted. A
# writable checkout can replace this script and gain root execution. The wheel
# is built from that trusted checkout by the invoking user; root does not
# execute build hooks or artifact code during installation, but a compromised
# wheel is still a compromised install. This installer does not accept or verify
# a separately supplied wheel artifact, and a checksum verified by code in the
# same untrusted checkout is not a trust boundary.
if [ "$(id -u)" -eq 0 ] && [ -z "${SUDO_USER:-}" ]; then
    echo "install.sh: run this through sudo, so the build runs as you and not as root" >&2
    echo "            (sudo ./install.sh)" >&2
    exit 1
fi
BUILD_USER=${SUDO_USER:-$(id -un)}
BUILD_GROUP=$(id -gn "$BUILD_USER")

WORK=""
STAGE=""
BACKUP=""
BACKUP_READY=no
INSTALL_STARTED=no
COMMITTED=no
CLEANUP_STATUS=0
CLEANUP_DONE=no
LIB_PREEXISTING=no
LIB_CREATED=no
SECURE_TMPROOT=""

secure_tmp_root() {
    # Inherited TMPDIR is caller-controlled. Privileged staging/backup must live
    # under a trusted, root-controlled parent that we create and validate.
    if [ -n "${SECURE_TMPROOT:-}" ]; then
        printf '%s\n' "$SECURE_TMPROOT"
        return 0
    fi
    local_parent=${AGENT_ISOLATION_INSTALL_TMPROOT:-/var/lib/agent-isolation}
    # Create the parent BEFORE the mode is set to the final one, and make it
    # traverse-only rather than 0700. Measured on Fedora 43: with the parent at
    # 0700 the unprivileged build could not create its output directory inside
    # WORK — it answers "failed to create directory ...: Permission denied" —
    # because the build runs as $SUDO_USER and cannot pass through a root-only
    # parent to reach a directory it owns. 0711 is the same rule already applied
    # to the staging root below: reachable by name, not listable.
    install -d -m 0700 -o root -g root "$local_parent"
    chmod 0711 "$local_parent"
    assert_trusted "$local_parent"
    SECURE_TMPROOT=$(TMPDIR= mktemp -d "$local_parent/install-tmp.XXXXXX")
    chown root:root "$SECURE_TMPROOT"
    # Traverse-only for non-root: builder can reach its dedicated WORK dir by
    # random name, but STAGE remains 0700 and the root is not listable.
    chmod 0711 "$SECURE_TMPROOT"
    printf '%s\n' "$SECURE_TMPROOT"
}

secure_mktemp_dir() {
    dir=$(TMPDIR= mktemp -d "$(secure_tmp_root)/$1.XXXXXX")
    chown root:root "$dir"
    # Traverse-only, for the same reason the staging root above is 0711: the build
    # runs as $SUDO_USER and must reach the subdirectories created for it inside
    # this one (WORK, STAGE/collections, STAGE/verify-home). At 0700 it cannot, and
    # the failure surfaces far from the cause — measured on Fedora 43 as
    # "the collections failed" with the galaxy output discarded. 0711 grants no
    # write and no listing: anything secret gets its own 0700 below.
    chmod 0711 "$dir"
    assert_trusted "$dir"
    printf '%s\n' "$dir"
}

cleanup() {
    CLEANUP_STATUS=$?
    set +e
    if [ "${CLEANUP_DONE:-no}" = yes ]; then
        exit "$CLEANUP_STATUS"
    fi
    CLEANUP_DONE=yes
    trap '' INT TERM
    if [ "${COMMITTED:-no}" = yes ]; then
        [ -n "${STAGE:-}" ] && rm -rf -- "$STAGE"
        [ -n "${WORK:-}" ] && rm -rf -- "$WORK"
        [ -n "${SECURE_TMPROOT:-}" ] && rmdir -- "$SECURE_TMPROOT" 2>/dev/null || true
        exit "$CLEANUP_STATUS"
    fi
    if [ "${INSTALL_STARTED:-no}" = yes ] && [ "${BACKUP_READY:-no}" = yes ] && [ -n "${BACKUP:-}" ] && [ -d "$BACKUP" ]; then
        rm -rf -- "$LIB"
        if mv -- "$BACKUP" "$LIB"; then
            echo "install.sh: rolled back to the previous installation" >&2
            BACKUP=""
            [ -n "${STAGE:-}" ] && rm -rf -- "$STAGE"
            [ -n "${WORK:-}" ] && rm -rf -- "$WORK"
            [ -n "${SECURE_TMPROOT:-}" ] && rmdir -- "$SECURE_TMPROOT" 2>/dev/null || true
        else
            echo "install.sh: COULD NOT ROLL BACK; the previous tree is at $BACKUP" >&2
            echo "install.sh: staging directory preserved at $STAGE" >&2
            [ -n "${WORK:-}" ] && rm -rf -- "$WORK"
        fi
    elif [ "${INSTALL_STARTED:-no}" = yes ]; then
        # First install or no usable backup: remove the partial install rather than
        # leaving a half-installed root-owned tree behind.
        rm -rf -- "$LIB"
        [ -n "${STAGE:-}" ] && rm -rf -- "$STAGE"
        [ -n "${WORK:-}" ] && rm -rf -- "$WORK"
        [ -n "${SECURE_TMPROOT:-}" ] && rmdir -- "$SECURE_TMPROOT" 2>/dev/null || true
    else
        # Install never started mutating $LIB. If this run created $LIB for a
        # first install, remove that empty directory; leave pre-existing installs
        # alone.
        if [ "${LIB_CREATED:-no}" = yes ] && [ "${LIB_PREEXISTING:-no}" = no ]; then
            rm -rf -- "$LIB"
        fi
        [ -n "${STAGE:-}" ] && rm -rf -- "$STAGE"
        [ -n "${WORK:-}" ] && rm -rf -- "$WORK"
        [ -n "${SECURE_TMPROOT:-}" ] && rmdir -- "$SECURE_TMPROOT" 2>/dev/null || true
    fi
    exit "$CLEANUP_STATUS"
}
# shellcheck disable=SC2064
trap 'cleanup' EXIT
trap 'CLEANUP_STATUS=130; exit 130' INT
trap 'CLEANUP_STATUS=143; exit 143' TERM

# Created 0755 and root-owned by this root-owned call: the mode is set explicitly
# because the caller's umask must not be able to loosen it. The cleanup trap is
# already active, so a failure after this point cannot leave a fresh first-install
# $LIB behind.
if [ -d "$LIB" ] || [ -L "$LIB" ] || [ -e "$LIB" ]; then
    LIB_PREEXISTING=yes
else
    LIB_CREATED=yes
fi
install -d -m 0755 -o root -g root "$LIB"

# Created ONCE, at top level: `$(secure_mktemp_dir ...)` runs in a subshell, so an
# assignment made inside it never reaches the caller. Measured without this line:
# every `secure_mktemp_dir` call created its OWN `install-tmp.*` root, and
# `cleanup`'s `rmdir "$SECURE_TMPROOT"` was a no-op because the variable was empty
# here — two empty roots were left behind after a successful install.
SECURE_TMPROOT=$(secure_tmp_root)

# The builder runs as the CALLER and must be able to write its output here, so the
# directory is owned by that user. The parent tmp root is trusted/root-only; WORK
# itself is a dedicated builder-owned subdirectory inside it.
WORK=$(secure_mktemp_dir work)
chown "$BUILD_USER:$BUILD_GROUP" "$WORK"
chmod 0755 "$WORK"

echo "Building the wheel as $BUILD_USER (no root code execution) ..."
# `runuser` first: it does not prompt (we are root) and it preserves the
# environment the builder needs. `su` is the fallback on systems without it; it
# asks for a password when it cannot switch silently, which fails closed here.
if ! runuser -u "$BUILD_USER" -- "$UV" build --wheel --out-dir "$WORK" "$SOURCE" >/dev/null 2>&1; then
    if ! su -s /bin/sh "$BUILD_USER" -c "'$UV' build --wheel --out-dir '$WORK' '$SOURCE'" >/dev/null 2>&1; then
        echo "install.sh: the unprivileged build failed; refusing to build as root" >&2
        exit 1
    fi
fi
WHEEL=$(ls "$WORK"/agent_isolation-*.whl 2>/dev/null | head -1)
if [ -z "$WHEEL" ]; then
    echo "install.sh: no wheel was produced in $WORK" >&2
    exit 1
fi
echo "  built $(basename "$WHEEL") ($(sha256sum "$WHEEL" | cut -c1-16)...)"

# The requirements come from the SAME artifact, not from the checkout.
/usr/bin/python3 - "$WHEEL" "$WORK/requirements.yml" <<'PYEOF'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    with z.open('agent_isolation/ansible/requirements.yml') as src:
        open(sys.argv[2], 'wb').write(src.read())
PYEOF

# THE LOCK IS THE RESOLUTION. A wheel carries RANGES (`click<9,>=8.1`), not
# versions, so installing it alone re-resolves and can produce a different runtime
# from the same commit. `uv export` turns the committed lock into a hashed
# requirements file and `uv pip install --require-hashes` verifies every
# downloaded artifact against those hashes; a lock/range disagreement or a bad
# artifact then fails instead of silently drifting.
#
# Exported by the BUILDING user from the checkout, then read by root as data.
# The file contains pinned versions and hashes, not executable code.
REQUIREMENTS="$WORK/requirements-hashed.txt"
if ! runuser -u "$BUILD_USER" -- "$UV" export \
        --project "$SOURCE" --format requirements-txt --frozen --no-emit-project \
        > "$REQUIREMENTS" 2>/dev/null; then
    echo "install.sh: cannot export the dependency lock; refusing to resolve freely" >&2
    exit 1
fi
if [ ! -s "$REQUIREMENTS" ]; then
    echo "install.sh: the exported lock is empty — is uv.lock committed?" >&2
    exit 1
fi
if ! grep -q -- '--hash=' "$REQUIREMENTS"; then
    echo "install.sh: exported requirements contain no hashes; refusing to install without lock verification" >&2
    exit 1
fi

# -- transaction: back up, install at the real path, verify, restore on failure --
#
# Installing into `$LIB` in place leaves the machine with a half-upgraded tree if
# `ansible-galaxy` or a verification step fails: new code, no collections, or a venv
# whose imports no longer resolve. The invariant established here: a failed upgrade
# leaves the PREVIOUS, WORKING install in place. `$WORK` is removed on normal exit;
# `$STAGE` is removed on commit/successful rollback/first-install cleanup, but kept
# when rollback cannot restore the backup so the only recoverable copy survives.
#
# The obvious design — assemble in a staging directory and `mv` it into place — does
# NOT work for a Python venv, and that was measured rather than assumed: every
# console script inside the venv carries an ABSOLUTE shebang pointing at the
# directory it was installed into, and `uv`'s `bin-dir/agent-account` is an absolute
# symlink. After the rename all of them point into a deleted staging path, so the
# command is dead. Installing at the real path and rolling back on failure avoids
# the whole class.
STAGE=$(secure_mktemp_dir stage)

# Keep the previous tree aside. `$LIB` may not exist on a first install.
if [ -L "$LIB" ] || { [ -e "$LIB" ] && [ ! -d "$LIB" ]; }; then
    echo "install.sh: $LIB exists but is not a directory; refusing to replace it" >&2
    exit 1
fi
if [ -d "$LIB" ]; then
    BACKUP="$STAGE/previous"
    cp -a -- "$LIB" "$BACKUP"
    # STAGE is traverse-only so the builder can reach its own subdirectories; the
    # backup is the one thing in it that must stay root-only.
    chmod 0700 "$BACKUP"
    BACKUP_READY=yes
fi

# Root never executes checkout code and never builds distributions. Dependencies
# come from the committed lock as hashed requirements; `--require-hashes`
# verifies every artifact, `--no-deps` keeps the wheel itself explicit, and
# `--no-build` refuses source builds. Past this point the install mutates $LIB
# and cleanup may restore or remove it.
INSTALL_STARTED=yes
echo "Installing the tool into $LIB ..."
install -d -m 0755 -o root -g root "$LIB"
# The interpreter is named, and its version is CHECKED before anything is
# installed. `requires-python` only covers the resolution; a version too new for
# the pinned Ansible installs cleanly and then fails at the first entry point with
# `AttributeError: module 'dataclasses' has no attribute '_is_type'` — measured on
# Python 3.15 with ansible-core 2.21.x, where `import ansible` still succeeds. The
# lock carries a per-Python fork (2.22.0 for >= 3.13, 2.21.x below), so a version
# outside the supported range is refused here instead of failing later.
PYV=$(/usr/bin/python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
# Match the exact "major.minor" this variable holds — `3.12.*` would require a
# THIRD component and never match `3.12`, which is how this guard first rejected
# a supported interpreter.
case "$PYV" in
    3.12|3.13|3.14|3.15) : ;;
    *)
        echo "install.sh: /usr/bin/python3 is $PYV, which this release does not support" >&2
        echo "            supported: 3.12 to 3.15 (see requires-python and the ansible-core fork in uv.lock)" >&2
        exit 1
        ;;
esac
echo "  interpreter $PYV"
"$UV" venv --clear --python /usr/bin/python3 "$LIB/agent-isolation" >/dev/null
"$UV" pip install \
    --python "$LIB/agent-isolation/bin/python" \
    --require-hashes \
    --no-deps \
    --no-build \
    -r "$REQUIREMENTS" >/dev/null
"$UV" pip install \
    --python "$LIB/agent-isolation/bin/python" \
    --no-deps \
    --no-build \
    "$WHEEL" >/dev/null
ln -sfn "$LIB/agent-isolation/bin/agent-account" "$BIN"

# The installed artifact comes from the invoking user's checkout, so anything
# that executes it runs as that user in a throwaway HOME, never as root.
VERIFY_HOME="$STAGE/verify-home"
install -d -m 0700 -o "$BUILD_USER" "$VERIFY_HOME"
run_as_builder() {
    if runuser -u "$BUILD_USER" -- env HOME="$VERIFY_HOME" "$@"; then
        return 0
    fi
    su -s /bin/sh "$BUILD_USER" -c "HOME=$(printf %s "$VERIFY_HOME" | sed "s/'/'\\\\''/g") $(printf " '%s'" "$@" | sed "s/'/'\\\\''/g")"
}
verify_as_builder() { run_as_builder "$@" >/dev/null 2>&1; }

echo "Installing Ansible collections ..."
COLLECTIONS_STAGE="$STAGE/collections"
install -d -m 0755 -o "$BUILD_USER" "$COLLECTIONS_STAGE"
verify_as_builder "$LIB/agent-isolation/bin/ansible-galaxy" collection install \
    -r "$WORK/requirements.yml" -p "$COLLECTIONS_STAGE" --force || {
    echo "install.sh: the collections failed; keeping the previous install" >&2
    exit 1
}
rm -rf "$LIB/collections"
mv "$COLLECTIONS_STAGE" "$LIB/collections"

# Verify the INSTALL, not the checkout. The artifact was built from a checkout
# the invoking user controls, so its code is not executed as root here.

verify_as_builder "$LIB/agent-isolation/bin/python" -I -c 'import agent_isolation' || {
    echo "install.sh: the installed code does not import; keeping the previous install" >&2
    exit 1
}
verify_as_builder "$LIB/agent-isolation/bin/python" -I -c 'import ansible' || {
    echo "install.sh: the installed Ansible does not import; keeping the previous install" >&2
    exit 1
}
verify_as_builder "$LIB/agent-isolation/bin/ansible-playbook" --version || {
    echo "install.sh: the installed playbook binary fails; keeping the previous install" >&2
    exit 1
}
[ -d "$LIB/collections/ansible_collections/ansible/posix" ] || {
    echo "install.sh: the installed collections are missing; keeping the previous install" >&2
    exit 1
}

chown -R root:root "$LIB"
chmod -R go-w "$LIB"

# Past this point the new tree is the one to keep, and the trap leaves it alone.
COMMITTED=yes

INSTALLED_CODE=$(run_as_builder "$LIB/agent-isolation/bin/python" -I -c 'import agent_isolation, os; print(os.path.dirname(agent_isolation.__file__))' 2>/dev/null || printf '%s' "$LIB/agent-isolation")
echo
echo "Installed:"
echo "  code        $INSTALLED_CODE"
echo "  collections $LIB/collections"
echo "  command     $BIN"
echo
echo "Next: $BIN apply --dry-run <worktree...>"
