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

    def _run(self, *, uid: int, mode: str, target: pathlib.Path) -> subprocess.CompletedProcess:
        """Run the guard with `target` reported as `uid`/`mode`."""
        shim = self.tmp / 'shim'
        shim.mkdir(exist_ok=True)
        (shim / 'stat').write_text(
            textwrap.dedent(f'''\
                #!/bin/sh
                case "$2" in
                    %u) echo {uid}; exit 0 ;;
                    %a) echo {mode}; exit 0 ;;
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

    def test_a_root_owned_read_only_directory_is_accepted(self):
        """The known-good case, so the guard is not simply always failing."""
        target = self.work / 'fine'
        target.mkdir()
        result = self._run(uid=0, mode='755', target=target)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('', result.stderr)

    def test_a_missing_directory_is_not_a_refusal(self):
        """A fresh host has no $LIB yet; creating it is the installer's job."""
        result = self._run(uid=0, mode='755', target=self.work / 'absent')
        self.assertEqual(0, result.returncode, result.stderr)


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
    """A symlink must be judged by its TARGET, and the uninstall must work.

    Measured on the first live install: `--uninstall` refused to remove its own
    `/usr/local/bin/agent-account`, because `stat` on a link reports 0777 whatever
    it points at. The installer could not undo itself.

    `stat` is shimmed to reproduce that exactly: 0777 without `-L`, 0755 with it.
    """

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='aa-link-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fn = _extract_assert_trusted()
        self.shim = self.tmp / 'shim'
        self.shim.mkdir()
        (self.shim / 'stat').write_text(
            textwrap.dedent('''\
                #!/bin/sh
                # Follow-link (stat -L) answers like the real target; a bare stat on a
                # link answers 0777, which is what Linux actually does.
                follow=no
                for a in "$@"; do [ "$a" = "-L" ] && follow=yes; done
                case "$*" in
                    *%u*) if [ "$follow" = yes ]; then echo 0; else echo 0; fi; exit 0 ;;
                    *%a*) if [ "$follow" = yes ]; then echo 755; else echo 777; fi; exit 0 ;;
                esac
                exec /usr/bin/stat "$@"
                '''),
            encoding='utf-8',
        )
        (self.shim / 'stat').chmod(0o755)

    def _run(self, target: pathlib.Path) -> subprocess.CompletedProcess:
        env = dict(os.environ, PATH=f'{self.shim}:{os.environ["PATH"]}')
        script = self.fn + f'\nassert_trusted "{target}"\n'
        return subprocess.run(['sh', '-c', script], capture_output=True, text=True,
                              check=False, env=env)

    def test_a_symlink_to_a_root_owned_read_only_target_is_accepted(self):
        """The install's own layout: /usr/local/bin/agent-account -> root-owned venv."""
        real = self.tmp / 'real-command'
        real.write_text('#!/bin/sh\n', encoding='utf-8')
        link = self.tmp / 'link'
        link.symlink_to(real)
        result = self._run(link)
        self.assertEqual(0, result.returncode,
                         f'a root-owned target must be accepted, got: {result.stderr}')
        self.assertEqual('', result.stderr)

    def test_the_guard_consults_the_target_not_the_link(self):
        """Pinned by shape as well: the link branch must ask for the followed stat."""
        text = INSTALL_SH.read_text(encoding='utf-8')
        self.assertIn('if [ -L "$path" ]', text)
        self.assertIn('stat -L -c %u "$path"', text)
        self.assertIn('stat -L -c "%a" "$path"', text)

    def test_a_dangling_symlink_does_not_abort_the_guard(self):
        link = self.tmp / 'dangling'
        link.symlink_to(self.tmp / 'nowhere')
        result = self._run(link)
        self.assertNotIn('Not a directory', result.stderr)
        self.assertNotIn('Traceback', result.stderr)


class BuildTrustTest(unittest.TestCase):
    """Root must never execute a build backend from the checkout (issue #5).

    Measured: `uv tool install .` runs the project's build backend, and a malicious
    hatch hook wrote a file. Under sudo that hook would run as ROOT.
    """

    def setUp(self):
        self.text = INSTALL_SH.read_text(encoding='utf-8')

    def test_root_installs_only_a_prebuilt_wheel(self):
        """`--no-build` is what makes a source tree unacceptable to root."""
        install = self.text.index('"$UV" tool install')
        segment = self.text[install:install + 400]
        self.assertIn('--no-build', segment)
        self.assertIn('"$WHEEL"', segment, 'the artifact, not the checkout')
        self.assertNotIn('"$SOURCE"', segment, 'the checkout must never be the install arg')

    def test_the_wheel_is_built_as_the_calling_user(self):
        self.assertIn('runuser -u "$BUILD_USER"', self.text)
        self.assertIn('build --wheel --out-dir "$WORK" "$SOURCE"', self.text)
        # The build directory must be writable by that user.
        self.assertIn('chown "$BUILD_USER" "$WORK"', self.text)

    def test_refuses_when_it_cannot_switch_to_the_caller(self):
        """Failing closed matters more than installing: root must not build."""
        self.assertIn('refusing to build as root', self.text)

    def test_the_requirements_come_from_the_wheel_not_the_checkout(self):
        """The manifest root reads must be the same artifact it installs."""
        galaxy = self.text.index('collection install')
        segment = self.text[max(0, galaxy - 300):galaxy + 300]
        self.assertIn('-r "$WORK/requirements.yml"', segment)
        self.assertNotIn('-r "$SOURCE', segment, 'the checkout must not supply the manifest')

    def test_a_root_shell_cannot_run_it_without_a_caller(self):
        """`sudo` provides SUDO_USER; a bare root shell has no unprivileged builder."""
        self.assertIn('if [ "$(id -u)" -eq 0 ] && [ -z "${SUDO_USER:-}" ]', self.text)


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

    def test_the_post_install_probe_uses_the_same_isolation_as_the_tool(self):
        """The check must exercise what `apply` will actually execute."""
        probe = "bin/python\" -I -c 'import agent_isolation"
        self.assertIn(probe, self.text)
        older = "bin/python\" -E -c 'import agent_isolation"
        self.assertNotIn(older, self.text)


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


if __name__ == '__main__':
    unittest.main()
