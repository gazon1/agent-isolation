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


if __name__ == '__main__':
    unittest.main()
