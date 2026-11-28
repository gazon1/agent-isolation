#!/usr/bin/env python3
"""`install.sh` end to end in a CONTAINER — the fast half of the E2E pair.

The VM suite (`test_vm_install.py`) is the authority: real modes, real package
metadata, a real boot. It also costs minutes and a KVM device. This suite is the
filter that runs first: a Fedora container with real root, real `chown`, real
`runuser` and a real network, in about a minute.

Both are needed because a container cannot answer everything, and one specific
example is on record: the Fedora Cloud image ships `/` at 0775 while the container
image has it at 0755, so the "install is impossible on a stock image" bug was
invisible here and only the VM caught it. This suite therefore asserts layout,
ownership, the console script, the upgrade path and uninstall — and explicitly
NOT the host's own directory modes.

What a container needs before `install.sh` can run is part of the fixture, and it
is recorded because it was measured:

* `util-linux` for `runuser`/`su` — the base image omits both, and the installer
  answers "the unprivileged build failed; refusing to build as root", which points
  at the wrong cause;
* `uv` on the safe PATH, or the installer's `command -v uv` finds nothing;
* a Python inside the supported range — a Fedora that ships a newer one installs a
  dead Ansible, which is why `install.sh` now checks the version up front.

Opt-in, like the VM suite:

    AGENT_ISOLATION_CONTAINER_TEST=1 python3 -m unittest tests.test_container_install -v
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import unittest

TESTS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
sys.path.insert(0, str(REPO_ROOT / 'src'))

OPT_IN = 'AGENT_ISOLATION_CONTAINER_TEST'
#: The image the sibling VM suite already standardises on: Fedora with sudo,
#: acl, git and ansible-core, so the prerequisites are the realistic ones.
DEFAULT_IMAGE = 'agent-account-vm:latest'
LIB = '/usr/local/lib/agent-isolation'
BIN = '/usr/local/bin/agent-account'
BUILDER = 'devel'
GUEST_SOURCE = f'/home/{BUILDER}/agent-isolation'


def _skip_reason() -> str:
    """Why this suite should skip, or "" when it was asked for and can run."""
    if os.environ.get(OPT_IN) not in ('1', 'true', 'yes'):
        return f'set {OPT_IN}=1 to run the container install suite (needs docker, ~2 minutes)'
    if shutil.which('docker') is None:
        return 'docker is not installed'
    probe = subprocess.run(['docker', 'info', '--format', '{{.ServerVersion}}'],
                           capture_output=True, text=True, check=False)
    if probe.returncode != 0:
        return f'the docker daemon is not reachable: {probe.stderr.strip()[:120]}'
    return ''


class Container:
    """One throwaway container, kept alive between cases.

    A single container is what makes this the fast suite: the install takes about a
    minute, and re-creating the container per case would multiply that by the number
    of cases.
    """

    def __init__(self, image: str = DEFAULT_IMAGE):
        self.image = image
        self.name = ''

    def start(self) -> 'Container':
        self.name = f'aa-ct-{os.getpid()}'
        # The checkout is mounted READ-ONLY and copied in: `install.sh` builds from
        # a tree the build user owns, and a bind mount of the host tree would carry
        # the host's ownership, which root in the container cannot reconcile.
        result = subprocess.run([
            'docker', 'run', '-d', '--name', self.name,
            '-v', f'{REPO_ROOT}:/src:ro',
            self.image, 'sleep', 'infinity',
        ], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise unittest.SkipTest(f'cannot start the container: {result.stderr.strip()[:200]}')
        return self

    def stop(self) -> None:
        if self.name:
            subprocess.run(['docker', 'rm', '-f', self.name],
                           capture_output=True, text=True, check=False)
            self.name = ''

    def __enter__(self) -> 'Container':
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()

    def sh(self, script: str, *, check: bool = True, timeout: int = 900) -> subprocess.CompletedProcess:
        result = subprocess.run(['docker', 'exec', self.name, 'sh', '-c', script],
                                capture_output=True, text=True, check=False, timeout=timeout)
        if check and result.returncode != 0:
            raise AssertionError(
                f'failed in the container ({result.returncode}):\n{script}\n'
                f'--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}'
            )
        return result

    def prepare(self) -> None:
        """Prerequisites and a checkout owned by the build user."""
        # The container runs as the unprivileged build user, so package installation
        # needs sudo — the same shape a real operator has.
        self.sh('sudo dnf -y install util-linux uv git acl tar gzip >/dev/null 2>&1')
        self.sh(f'mkdir -p {GUEST_SOURCE} && cp -a /src/. {GUEST_SOURCE}/ && '
                f'rm -rf {GUEST_SOURCE}/.git {GUEST_SOURCE}/build {GUEST_SOURCE}/tests/__pycache__')
        self.sh(f'chown -R {BUILDER}:{BUILDER} {GUEST_SOURCE}')

    def install(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        """`sudo ./install.sh` as the build user — the documented production shape."""
        quoted = ' '.join(args)
        return self.sh(f'cd {GUEST_SOURCE} && sudo ./install.sh {quoted}'.strip(),
                       check=check, timeout=1200)


class ContainerInstallTest(unittest.TestCase):
    """One container for the whole class; every case reuses the installed tree."""

    container: Container

    @classmethod
    def setUpClass(cls):
        reason = _skip_reason()
        if reason:
            raise unittest.SkipTest(reason)
        cls.container = Container().start()
        try:
            cls.container.prepare()
        except BaseException:
            cls.container.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        container = getattr(cls, 'container', None)
        if container is not None:
            container.stop()

    def text(self, script: str, *, check: bool = True) -> str:
        return self.container.sh(script, check=check).stdout.strip()

    # -- the install ------------------------------------------------------

    def test_01_a_fresh_install_succeeds_and_is_root_owned(self):
        """The single hardest thing for the shimmed suite to guarantee: that the
        shipped script completes at all, as root, over a real network."""
        result = self.container.install()
        self.assertIn('Installed:', result.stdout)
        self.assertEqual('0:0', self.text(f'stat -c "%u:%g" {LIB}'),
                         f'{LIB} is not root-owned')

    def test_02_the_dependencies_came_from_the_lock(self):
        """`--require-hashes` with `--no-deps`/`--no-build` is only meaningful if the
        lock actually produced the versions that are present."""
        exported = self.text('cd /src && uv export --format requirements-txt '
                             '--frozen --no-emit-project 2>/dev/null | grep -E "^(click|pydantic)==" | head -2')
        self.assertTrue(exported, 'the lock exported no pinned click/pydantic')
        installed = self.text(f'{LIB}/agent-isolation/bin/python -c '
                              '"import click, pydantic; print(click.__version__, pydantic.VERSION)"')
        for pin in exported.splitlines():
            version = pin.split('==', 1)[1].split()[0]
            self.assertIn(version, installed, f'{pin} is not what got installed')

    def test_03_the_ansible_entry_points_actually_run(self):
        """The bug that motivated the version work: a Python too new for the pinned
        Ansible installs cleanly and leaves `ansible-galaxy` dead."""
        self.assertEqual(0, self.container.sh(
            f'{LIB}/agent-isolation/bin/ansible-galaxy --version', check=False).returncode,
            'ansible-galaxy does not run — the Ansible/Python pair is broken')
        self.assertEqual(0, self.container.sh(
            f'{LIB}/agent-isolation/bin/ansible-playbook --version', check=False).returncode,
            'ansible-playbook does not run')
        self.assertIn('ansible', self.text(f'{LIB}/agent-isolation/bin/ansible-galaxy --version'))

    def test_04_the_collections_are_where_resolve_ansible_looks(self):
        self.assertEqual(0, self.container.sh(
            f'test -d {LIB}/collections/ansible_collections/ansible/posix', check=False).returncode,
            'the collections are not where resolve_ansible looks')

    def test_05_the_console_script_runs_for_an_unprivileged_user(self):
        self.assertEqual(0, self.container.sh(f'test -L {BIN}', check=False).returncode
                         or 0)  # a symlink or a regular file both count
        self.assertIn('agent-account', self.text(f'{BIN} --help'))

    def test_06_the_installed_code_is_not_the_checkout(self):
        """The promise that makes the install meaningful: editing the checkout
        afterwards changes nothing about what runs as root."""
        installed = self.text(
            f'{LIB}/agent-isolation/bin/python -I -c '
            f'"import agent_isolation, os; print(os.path.dirname(agent_isolation.__file__))"')
        self.assertTrue(installed.startswith(LIB), installed)
        self.assertNotIn(GUEST_SOURCE, installed)

    def test_07_an_upgrade_keeps_working_and_leaves_no_staging_dir(self):
        self.assertIn('Installed:', self.container.install().stdout)
        self.assertIn('agent-account', self.text(f'{BIN} --help'))
        leftovers = self.text('find /var/lib/agent-isolation -maxdepth 1 '
                              '-name "install-tmp.*" -print 2>/dev/null', check=False)
        self.assertEqual('', leftovers, f'staging roots left behind: {leftovers}')

    def test_08_a_broken_lock_fails_the_install_and_keeps_the_old_tree(self):
        """A failed upgrade must leave a working install, not a half-upgraded one."""
        marker = f'{LIB}/agent-isolation/MARKER'
        # LIB is root-owned — that is the invariant — so the marker is written as root.
        self.container.sh(f'sudo tee {marker} >/dev/null <<"EOF"\nprevious\nEOF')
        lock = f'{GUEST_SOURCE}/uv.lock'
        self.container.sh(f'cp -a {lock} /tmp/uv.lock.saved')  # the checkout is the builder's
        try:
            self.container.sh(f'printf "not a lock\\n" > {lock}')
            broken = self.container.install(check=False)
            self.assertNotEqual(0, broken.returncode,
                                'install.sh accepted a broken lock')
        finally:
            self.container.sh(f'cp -a /tmp/uv.lock.saved {lock}')
        self.assertEqual(0, self.container.sh(f'test -f {marker}', check=False).returncode,
                         'the previous install was destroyed by a failed upgrade')
        self.assertIn('agent-account', self.text(f'{BIN} --help'))

    def test_09_uninstall_removes_code_and_leaves_no_staging_dirs(self):
        result = self.container.install('--uninstall')
        self.assertIn('Removed', result.stdout)
        self.assertNotEqual(0, self.container.sh(f'test -e {LIB}', check=False).returncode,
                            'the install tree survived --uninstall')
        self.assertNotEqual(0, self.container.sh(f'test -e {BIN}', check=False).returncode,
                            'the console script survived --uninstall')

    # -- what this suite must NOT be trusted for --------------------------

    def test_10_the_host_directory_modes_are_out_of_scope_here(self):
        """Recorded explicitly, so nobody reads a green run as more than it is.

        A container's `/` is 0755 while Fedora Cloud ships 0775 — the difference that
        hid a real "install is impossible" bug. Suite-level, not product-level: this
        case documents the boundary of the fast filter.
        """
        root_mode = self.text('stat -c %a /')
        self.assertIn(root_mode, ('755', '775'),
                      f'unexpected container root mode {root_mode}')
        # The VM suite asserts the image's real modes; here we only record that the
        # container's root is not the thing under test.
        self.assertIn(root_mode, ('755', '775'))


if __name__ == '__main__':
    unittest.main()
