#!/usr/bin/env python3
"""Tests for `install.sh` — the root-owned install the privileged half runs from.

Running the installer for real demands root, so these test the guard that decides
whether root installs into a directory at all. They exercise the SHIPPED shell
function, extracted from `install.sh`, rather than a Python rewrite of it.

`stat` is shimmed on PATH to answer the ownership/mode question, because a test
process cannot chown a directory to a foreign uid without root. Everything else —
the loop, the comparisons, the messages, the ordering — is the real code.
"""

import os
import pathlib
import shutil
import stat as stat_module
import subprocess
import tempfile
import textwrap
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / 'install.sh'


def _extract_assert_trusted() -> str:
    """The `assert_trusted` function, verbatim, out of `install.sh`."""
    text = INSTALL_SH.read_text(encoding='utf-8')
    start = text.index('assert_trusted() {')
    end = text.index('\n}\n', start) + len('\n}\n')
    return text[start:end]


class AssertTrustedTest(unittest.TestCase):
    """The guard that decides whether root installs into a directory."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='aa-install-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fn = _extract_assert_trusted()
        self.work = self.tmp / 'work'
        self.work.mkdir()

    def _run(self, *, uid: int, mode: str, target: pathlib.Path,
             trusted: tuple[pathlib.Path, ...] = ()) -> subprocess.CompletedProcess:
        """Run the guard with `target` reported as `uid`/`mode`."""
        shim = self.tmp / 'shim'
        shim.mkdir(exist_ok=True)
        trusted_cases = ''.join(
            f'''
                    "{p}")
                        case "$*" in
                            *%u*) echo 0; exit 0 ;;
                            *%a*) echo 755; exit 0 ;;
                        esac ;;'''
            for p in trusted
        )
        (shim / 'stat').write_text(
            textwrap.dedent(f'''\
                #!/bin/sh
                # The guard walks every ancestor, so only the TARGET answers with the
                # test's values; real stat answers for "/" and the directories above.
                last=""
                for a in "$@"; do last="$a"; done
                case "$last" in
                    "{target}")
                        case "$*" in
                            *%u*) echo {uid}; exit 0 ;;
                            *%a*) echo {mode}; exit 0 ;;
                        esac ;;{trusted_cases}
                esac
                exec /usr/bin/stat "$@"
                '''),
            encoding='utf-8',
        )
        (shim / 'stat').chmod(0o755)
        env = dict(os.environ, PATH=f'{shim}:{os.environ["PATH"]}')
        script = self.fn + f'\nassert_trusted "{target}"\n'
        return subprocess.run(['sh', '-c', script], capture_output=True, text=True,
                              check=False, env=env)

    def test_a_directory_owned_by_somebody_else_is_refused(self):
        """The attack: pre-create the install root as an unprivileged user.

        Root would then run `uv tool install` inside a tree the attacker owns, and
        the later `chown -R root:root` comes too late — the content is already in.
        """
        target = self.work / 'agent-isolation'
        target.mkdir()
        result = self._run(uid=12345, mode='755', target=target)
        self.assertNotEqual(0, result.returncode, 'a foreign-owned directory was accepted')
        self.assertIn('not root', result.stderr)

    def test_a_group_writable_directory_is_refused(self):
        """Group write is a path for a non-root user to replace the code."""
        target = self.work / 'grouppy'
        target.mkdir()
        result = self._run(uid=0, mode='775', target=target)
        self.assertNotEqual(0, result.returncode, 'a group-writable directory was accepted')
        self.assertIn('group- or world-writable', result.stderr)

    def test_a_world_writable_directory_is_refused(self):
        target = self.work / 'open'
        target.mkdir()
        result = self._run(uid=0, mode='777', target=target)
        self.assertNotEqual(0, result.returncode, 'a world-writable directory was accepted')
        self.assertIn('group- or world-writable', result.stderr)

    def test_a_path_under_a_world_writable_ancestor_is_refused(self):
        """The walk covers EVERY component, so `/tmp/...` never passes.

        This is the point of the fix rather than a limitation: a root-owned file in
        a directory any user can write is a file any user can replace.
        """
        target = self.work / 'fine'
        target.mkdir()
        result = self._run(uid=0, mode='755', target=target)
        self.assertNotEqual(0, result.returncode, 'an unusable ancestor must refuse')
        # Ownership is checked before mode, so a directory owned by this user is
        # named by uid. Either message is a refusal for the right reason.
        self.assertTrue('not root' in result.stderr or 'world-writable' in result.stderr,
                        result.stderr)

    def test_a_missing_directory_under_a_trusted_ancestor_is_accepted(self):
        """A fresh host has no $LIB yet; its existing ancestor must be trusted."""
        trusted = []
        p = self.work
        while True:
            trusted.append(p)
            if p == p.parent:
                break
            p = p.parent
        result = self._run(uid=0, mode='755', target=self.work / 'absent',
                           trusted=tuple(trusted))
        self.assertEqual(0, result.returncode, result.stderr)

    def test_a_nonexistent_prefix_under_a_writable_ancestor_is_refused(self):
        """An absent target must not skip validation of its existing ancestor."""
        prefix = self.tmp / 'writable'
        prefix.mkdir()
        prefix.chmod(0o777)
        target = prefix / 'new-prefix' / 'lib'
        result = self._run(uid=0, mode='755', target=target, trusted=(prefix,))
        self.assertNotEqual(0, result.returncode, 'a writable ancestor was accepted')
        self.assertTrue('not root' in result.stderr or 'world-writable' in result.stderr,
                        result.stderr)

    def test_a_partially_existing_prefix_under_a_writable_ancestor_is_refused(self):
        """A partially created prefix still has an attacker-controlled ancestor."""
        prefix = self.tmp / 'writable-partial'
        prefix.mkdir()
        prefix.chmod(0o777)
        (prefix / 'new-prefix').mkdir()
        target = prefix / 'new-prefix' / 'lib'
        result = self._run(uid=0, mode='755', target=target, trusted=(prefix,))
        self.assertNotEqual(0, result.returncode, 'a writable ancestor was accepted')
        self.assertTrue('not root' in result.stderr or 'world-writable' in result.stderr,
                        result.stderr)


class GuardOrderTest(unittest.TestCase):
    """The guard must run BEFORE `uv`, not after it."""

    def setUp(self):
        self.text = INSTALL_SH.read_text(encoding='utf-8')

    def test_the_install_directory_itself_is_checked(self):
        """Checking only the PARENTS is the gap: $LIB can be foreign-owned."""
        self.assertIn('assert_trusted "$PREFIX/lib" "$PREFIX/bin" "$LIB"', self.text)

    def test_the_guard_runs_before_the_directory_is_created(self):
        guard = self.text.index('assert_trusted "$PREFIX/lib" "$PREFIX/bin" "$LIB"')
        create = self.text.index('install -d -m 0755 -o root -g root "$LIB"')
        self.assertLess(guard, create, 'the guard runs before the directory is created')

    def test_the_guard_runs_before_uv_writes_anything(self):
        guard = self.text.index('assert_trusted "$PREFIX/lib" "$PREFIX/bin" "$LIB"')
        uv = self.text.index('uv tool install')
        self.assertLess(guard, uv, 'the guard runs before uv installs as root')

    def test_the_created_directory_has_an_explicit_secure_mode(self):
        """`mkdir -p` honours the caller's umask; `install -d -m` does not."""
        self.assertIn('install -d -m 0755 -o root -g root "$LIB"', self.text)
        self.assertNotIn('mkdir -p "$LIB"', self.text)


class SymlinkGuardTest(unittest.TestCase):
    """Real filesystem layouts, not mocked metadata.

    The guard decides whether root installs into a directory, and its correctness
    is entirely about the actual tree: which component is writable, where a link
    points, whether an ancestor is a link. A `stat` shim cannot express that, so
    these tests build the trees for real and run the shipped function under `sh`.
    """

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='aa-link-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fn = _extract_assert_trusted()

    def _run(self, target: pathlib.Path) -> subprocess.CompletedProcess:
        script = self.fn + f'\nassert_trusted "{target}"\n'
        return subprocess.run(['sh', '-c', script], capture_output=True, text=True, check=False)

    def _writable(self, path: pathlib.Path) -> pathlib.Path:
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o777)
        return path

    def test_a_symlink_inside_a_world_writable_directory_is_refused(self):
        """The measured attack: the TARGET is root-owned, the DIRECTORY is not.

        `readlink -f` alone answers the target and hides this, which is why both the
        path as given and its canonical form are walked.
        """
        holder = self._writable(self.tmp / 'holder')
        real = self.tmp / 'real-target'
        real.write_text('#!/bin/sh\n', encoding='utf-8')
        link = holder / 'cmd'
        link.symlink_to(real)
        result = self._run(link)
        self.assertNotEqual(0, result.returncode, 'a link in a writable dir was accepted')
        # Ownership is checked before mode, so a directory owned by this user is
        # named by uid. Either message is a refusal for the right reason.
        self.assertTrue('world-writable' in result.stderr or 'not root' in result.stderr,
                        result.stderr)

    def test_a_symlinked_parent_directory_is_judged_at_its_real_location(self):
        """`/usr/sbin -> bin` is the everyday case; a writable one is the attack."""
        real_parent = self._writable(self.tmp / 'realparent')
        (real_parent / 'child').mkdir()
        linked = self.tmp / 'linkedparent'
        linked.symlink_to(real_parent, target_is_directory=True)
        result = self._run(linked / 'child')
        self.assertNotEqual(0, result.returncode, 'a writable real parent was accepted')

    def test_a_dangling_symlink_does_not_abort_the_guard(self):
        """`[ -e ]` is false for a dangling link, so it is skipped, not crashed on."""
        link = self.tmp / 'dangling'
        link.symlink_to(self.tmp / 'nowhere')
        result = self._run(link)
        self.assertNotIn('Not a directory', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertNotIn('cannot canonicalise', result.stderr)

    def test_a_path_whose_ancestors_are_all_trusted_is_accepted(self):
        """The known-good case, so the guard is not simply always failing.

        Built under `/` rather than `/tmp`, because `/tmp` is 1777 and the walk
        correctly refuses it — that is the check working, not a false positive.
        """
        base = pathlib.Path('/usr/local/lib')
        if not base.is_dir() or os.geteuid() != 0:
            self.skipTest('needs a root-owned /usr/local/lib and root')
        target = pathlib.Path(tempfile.mkdtemp(prefix='aa-ok-', dir=str(base)))
        self.addCleanup(shutil.rmtree, target, True)
        target.chmod(0o755)
        result = self._run(target)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('', result.stderr)

    def test_the_walk_uses_the_followed_stat(self):
        """Pinned by shape: `/usr/sbin` is a link to `bin` and reports 0777.

        Without `-L` every normal Fedora install would be refused — measured.
        """
        text = INSTALL_SH.read_text(encoding='utf-8')
        self.assertIn('stat -L -c %u "$check"', text)
        self.assertIn('stat -L -c "%a" "$check"', text)


def _extract_verify_helpers() -> str:
    text = INSTALL_SH.read_text(encoding='utf-8')
    start = text.index('VERIFY_HOME="$STAGE/verify-home"')
    end = text.index('\necho "Installing Ansible collections ..."', start)
    return text[start:end]


class ArtifactTrustBoundaryTest(unittest.TestCase):
    """Install-time verification must not execute checkout-controlled code as root."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='aa-verify-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fn = _extract_verify_helpers()

    def test_malicious_package_is_not_executed_as_root_during_verification(self):
        stage = self.tmp / 'stage'
        lib = self.tmp / 'lib' / 'agent-isolation' / 'bin'
        stage.mkdir()
        lib.mkdir(parents=True)
        marker = self.tmp / 'ran-as-root'
        # A malicious "python" that would record root execution.
        malicious = lib / 'python'
        malicious.write_text(
            '#!/bin/sh\n[ "$(id -u)" -eq 0 ] && echo root > ' + str(marker) + '\nexit 0\n',
            encoding='utf-8',
        )
        malicious.chmod(0o755)
        shim = self.tmp / 'shim'
        shim.mkdir()
        # runuser just runs the command as the current user for this test.
        (shim / 'runuser').write_text('#!/bin/sh\nshift; shift; shift; exec "$@"\n', encoding='utf-8')
        (shim / 'runuser').chmod(0o755)
        env = dict(os.environ, PATH=f'{shim}:{os.environ["PATH"]}')
        script = textwrap.dedent(f"""\
            set -eu
            STAGE={stage}
            LIB={self.tmp / 'lib'}
            BUILD_USER=$(id -un)
            {self.fn}
            verify_as_builder "$LIB/agent-isolation/bin/python" -I -c 'import agent_isolation'
            """)
        result = subprocess.run(['sh', '-c', script], capture_output=True, text=True,
                                check=False, env=env)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(marker.exists(), 'artifact code executed as root during verification')


class ToolTrustTest(unittest.TestCase):
    """Every binary the installer runs AS ROOT is checked, not just the code."""

    def setUp(self):
        self.text = INSTALL_SH.read_text(encoding='utf-8')

    def test_uv_itself_is_checked_before_it_runs(self):
        """Measured on Fedora: `command -v uv` answered a mode-0777 mise shim owned
        by uid 1000. Running THAT as root is the hole the install exists to close."""
        guard = self.text.index('assert_trusted "$UV"')
        first_uv = self.text.index('tool install')
        self.assertLess(guard, first_uv, 'uv is trusted-checked before it runs')
        self.assertIn('UV=$(command -v uv', self.text, 'the path is resolved once, then checked')

    def test_the_interpreter_is_pinned_to_root_s_own_python(self):
        """A bare `--python 3.12` lets uv resolve into a user-owned download."""
        self.assertIn('--python /usr/bin/python3', self.text)
        self.assertNotIn('--python 3.12', self.text)

    def test_post_install_verification_does_not_execute_artifact_as_root(self):
        """The installed artifact comes from an untrusted checkout; root must not import it."""
        self.assertIn('verify_as_builder', self.text)
        self.assertIn('runuser -u "$BUILD_USER"', self.text)
        self.assertNotRegex(
            self.text,
            r'(?m)^"\$LIB/agent-isolation/bin/python" -I -c \'import agent_isolation\'',
            'root must not import the installed artifact directly',
        )
        self.assertNotRegex(
            self.text,
            r'(?m)^"\$LIB/agent-isolation/bin/python" -I -c \'import ansible\'',
            'root must not import the installed artifact directly',
        )
        self.assertNotRegex(
            self.text,
            r'(?m)^"\$LIB/agent-isolation/bin/ansible-galaxy" collection install',
            'ansible-galaxy from the artifact must not run as root',
        )
        self.assertIn('ansible-galaxy" collection install', self.text)


class DependencyLockTest(unittest.TestCase):
    """The committed lock must be what gets installed, not a date cutoff.

    A wheel carries RANGES (`click<9,>=8.1`), so installing it alone re-resolves
    and can produce a different runtime from the same commit. Measured: the
    installed `click` was 8.5.1 while nothing forced it.
    """

    def setUp(self):
        self.text = INSTALL_SH.read_text(encoding='utf-8')
        self.lock = REPO_ROOT / 'uv.lock'

    def test_the_lock_file_is_committed(self):
        self.assertTrue(self.lock.is_file(), 'uv.lock is the authoritative pin')

    def test_the_lock_is_exported_and_passed_as_constraints(self):
        self.assertIn('"$UV" export', self.text)
        self.assertIn('--format requirements-txt', self.text)
        install = self.text.index('"$UV" tool install')
        segment = self.text[install:install + 400]
        self.assertIn('--constraints "$CONSTRAINTS"', segment)

    def test_a_missing_lock_refuses_instead_of_resolving_freely(self):
        self.assertIn('cannot export the dependency lock', self.text)
        self.assertIn('is uv.lock committed?', self.text)

    def test_the_date_cutoff_is_not_the_pin(self):
        """`--exclude-newer` limits the index window; it does NOT reproduce a lock."""
        self.assertNotIn('--exclude-newer', self.text,
                         'a date cutoff is not the locked resolution')

    def test_every_runtime_dependency_is_pinned_in_the_lock(self):
        import re

        text = self.lock.read_text(encoding='utf-8')
        for name in ('click', 'pydantic', 'ansible-core'):
            entry = re.search(rf'name = "{re.escape(name)}"\nversion = "([^"]+)"', text)
            self.assertIsNotNone(entry, f'{name} is pinned in uv.lock')


class UpgradeSafetyTest(unittest.TestCase):
    """A failed upgrade must not leave the host without a working install."""

    def setUp(self):
        self.text = INSTALL_SH.read_text(encoding='utf-8')

    def test_the_build_happens_before_the_installed_tree_is_touched(self):
        build = self.text.index('build --wheel --out-dir "$WORK"')
        install = self.text.index('"$UV" tool install')
        self.assertLess(build, install, 'a build failure leaves the old install alone')

    def test_a_failed_build_aborts_before_any_install(self):
        refusal = self.text.index('refusing to build as root')
        next_install = self.text.index('"$UV" tool install')
        self.assertLess(refusal, next_install)

    def test_uninstall_removes_both_paths(self):
        self.assertIn('rm -f "$BIN"', self.text)
        self.assertIn('rm -rf "$LIB"', self.text)

    def test_uninstall_refuses_a_foreign_installed_tree(self):
        """Uninstall is root too: it must not remove a tree somebody else owns."""
        uninstall = self.text.index('if [ "$UNINSTALL" = yes ]')
        segment = self.text[uninstall:uninstall + 200]
        self.assertIn('assert_trusted "$LIB" "$BIN"', segment)


class TrustedPathTest(unittest.TestCase):
    """A trust check whose OWN tools come from the caller's PATH is not a check.

    Measured: `sudo env PATH=/tmp/hijack:$PATH ./install.sh` executed a hostile
    `stat` from that directory, and `assert_trusted` verifies paths with `stat`,
    `readlink` and `dirname`.
    """

    def setUp(self):
        self.text = INSTALL_SH.read_text(encoding='utf-8')

    def test_the_path_is_reset_before_anything_else_runs(self):
        text = self.text
        reset = text.index('PATH=/usr/sbin:/usr/bin:/sbin:/bin')
        # Nothing that could resolve a binary appears before it.
        first_use = min(
            position for position in
            (text.find('$(command'), text.find('assert_trusted "'))
            if position != -1
        )
        self.assertLess(reset, first_use, 'the safe PATH is established first')

    def test_uv_is_resolved_after_the_reset(self):
        self.assertLess(
            self.text.index('PATH=/usr/sbin:/usr/bin:/sbin:/bin'),
            self.text.index('UV=$(command -v uv'),
        )


def _extract_cleanup() -> str:
    """The `cleanup` function, verbatim, out of `install.sh`."""
    text = INSTALL_SH.read_text(encoding='utf-8')
    start = text.index('cleanup() {')
    end = text.index("trap 'cleanup' EXIT INT TERM", start)
    return text[start:end]


class RestoreBehaviorTest(unittest.TestCase):
    """Restore must not destroy the only recoverable backup; normal paths clean WORK."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='aa-restore-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fn = _extract_cleanup()

    def _run(self, *, fail_mv: bool, backup_exists: bool,
             committed: bool = False) -> subprocess.CompletedProcess:
        lib = self.tmp / 'lib'
        stage = self.tmp / 'stage'
        work = self.tmp / 'work'
        backup = stage / 'previous'
        stage.mkdir()
        work.mkdir()
        (work / 'wheel.whl').write_text('built', encoding='utf-8')
        lib.mkdir()
        (lib / 'partial').write_text('new', encoding='utf-8')
        if backup_exists:
            backup.mkdir()
            (backup / 'old').write_text('old', encoding='utf-8')
        shim = self.tmp / 'shim'
        shim.mkdir()
        real_rm = shutil.which('rm', path='/usr/bin:/bin') or '/bin/rm'
        os.symlink(real_rm, shim / 'rm')
        if fail_mv:
            (shim / 'mv').write_text('#!/bin/sh\nexit 1\n', encoding='utf-8')
            (shim / 'mv').chmod(0o755)
        env = dict(os.environ, PATH=f'{shim}:{os.environ["PATH"]}')
        script = textwrap.dedent(f"""\
            set -eu
            LIB={lib}
            STAGE={stage}
            WORK={work}
            BACKUP={backup if backup_exists else ''}
            COMMITTED={'yes' if committed else 'no'}
            CLEANUP_STATUS=0
            {self.fn}
            trap 'cleanup' EXIT
            exit 1
            """)
        return subprocess.run(['sh', '-c', script], capture_output=True, text=True,
                              check=False, env=env)

    def test_failed_restore_preserves_backup_and_stage(self):
        result = self._run(fail_mv=True, backup_exists=True)
        self.assertNotEqual(0, result.returncode)
        backup = self.tmp / 'stage' / 'previous'
        self.assertTrue((backup / 'old').is_file(), 'backup was destroyed')
        self.assertTrue((self.tmp / 'stage').is_dir(), 'stage containing backup was deleted')
        self.assertFalse((self.tmp / 'work').exists(), 'work left behind on failed restore')
        self.assertIn('staging directory preserved', result.stderr)

    def test_failed_first_install_removes_partial_tree(self):
        result = self._run(fail_mv=False, backup_exists=False)
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.tmp / 'lib').exists(), 'partial install left behind')
        self.assertFalse((self.tmp / 'stage').exists(), 'stage left behind')
        self.assertFalse((self.tmp / 'work').exists(), 'work left behind on normal failure')

    def test_successful_commit_removes_work_and_stage(self):
        result = self._run(fail_mv=False, backup_exists=True, committed=True)
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.tmp / 'stage').exists(), 'stage left behind on commit')
        self.assertFalse((self.tmp / 'work').exists(), 'work left behind on commit')


class TransactionTest(unittest.TestCase):
    """A failed upgrade must leave a working install, whatever failed."""

    def setUp(self):
        self.text = INSTALL_SH.read_text(encoding='utf-8')

    def test_the_previous_tree_is_copied_before_installing(self):
        backup = self.text.index('cp -a "$LIB" "$BACKUP"')
        # The FIRST real invocation; a comment mentioning it does not count.
        install = self.text.index('UV_TOOL_DIR="$LIB" UV_TOOL_BIN_DIR="$LIB/bin-dir" "$UV" tool install')
        self.assertLess(backup, install, 'the backup exists before the tree changes')

    def test_a_cleanup_trap_covers_every_failure_path(self):
        self.assertIn("trap 'cleanup' EXIT INT TERM", self.text)

    def test_each_install_step_fails_loudly_and_stops(self):
        for message in (
            'the collections failed',
            'the installed code does not import',
            'the installed Ansible does not import',
            'the installed playbook binary fails',
            'the installed collections are missing',
        ):
            self.assertIn(message, self.text, message)

    def test_a_committed_install_is_not_rolled_back(self):
        """Otherwise a successful install would delete itself on exit."""
        self.assertIn('COMMITTED=yes', self.text)
        self.assertIn('[ "$COMMITTED" = yes ]', self.text)

    def test_the_staging_swap_is_not_used_for_a_venv(self):
        """Measured: `mv` a venv and every console script's absolute shebang breaks.

        The install therefore happens at its real path, with a backup/restore.
        """
        self.assertNotIn('mv "$NEW" "$LIB"', self.text)

    def test_failed_restore_preserves_the_only_backup(self):
        """A backup that cannot be restored must not be deleted by the trap."""
        restore_else = self.text.index('COULD NOT ROLL BACK; the previous tree is at $BACKUP')
        else_block = self.text[restore_else:self.text.index('rm -rf -- "$WORK"', restore_else)]
        self.assertNotIn('BACKUP=""', else_block)
        self.assertIn('staging directory preserved at $STAGE', else_block)
        self.assertNotIn('rm -rf -- "$STAGE"', else_block)

    def test_a_failed_first_install_removes_the_partial_tree(self):
        """With no backup, a failed install must not leave a partial root-owned tree."""
        cleanup = self.text[self.text.index('cleanup() {'):self.text.index("trap 'cleanup'")]
        self.assertIn('First install or no backup', cleanup)
        self.assertIn('rm -rf -- "$LIB"', cleanup)
        self.assertIn('rm -rf -- "$STAGE" "$WORK"', cleanup)

    def test_work_is_cleaned_on_commit_and_normal_failure(self):
        cleanup = self.text[self.text.index('cleanup() {'):self.text.index("trap 'cleanup'")]
        self.assertIn('rm -rf -- "$STAGE" "$WORK"', cleanup)


if __name__ == '__main__':
    unittest.main()
