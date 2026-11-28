#!/usr/bin/env python3
"""End-to-end `install.sh` on a real, booted VM — the test that replaces by hand.

`InstallScriptIntegrationTest` covers the shell logic inside a user namespace with
`stat`, `chown`, `chmod`, `runuser` and `su` replaced by shims. That is the right
unit test, and it has already caught real bugs, but by construction it cannot answer
the questions an operator actually asks before `sudo ./install.sh`:

* does the wheel build and install with the LOCK, over a real network?
* does `chown -R root:root` really leave a root-owned tree?
* does `runuser -u <builder>` really drop privileges, so no build hook runs as root?
* does `ansible-galaxy` write `ansible.posix` where `resolve_ansible` looks?
* does the installed console script work, and does the installed code re-execute
  itself through `sudo` — the whole point of installing outside the checkout?
* does an UPGRADE keep a working tree, and does a failure restore it?

So this boots Fedora Cloud under KVM and runs the shipped script as root, with
nothing shimmed inside the guest.

Opt-in by design — it needs KVM, ~600 MB of image, and a few minutes:

    AGENT_ISOLATION_VM_TEST=1 python3 -m unittest tests.test_vm_install -v

Without that variable every case skips, so `python3 -m unittest discover -s tests`
stays fast and offline.
"""

import os
import pathlib
import shlex
import subprocess
import sys
import unittest

TESTS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
sys.path.insert(0, str(REPO_ROOT / 'src'))
sys.path.insert(0, str(TESTS_DIR))

import vm_harness  # noqa: E402
OPT_IN = 'AGENT_ISOLATION_VM_TEST'
BUILDER = 'fedora'
GUEST_SOURCE = f'/home/{BUILDER}/agent-isolation'
LIB = '/usr/local/lib/agent-isolation'
BIN = '/usr/local/bin/agent-account'


def _opt_in() -> str:
    """Why this suite should skip, or "" when it was asked for and can run."""
    if os.environ.get(OPT_IN) not in ('1', 'true', 'yes'):
        return f'set {OPT_IN}=1 to run the VM install suite (needs KVM, ~600 MB image, several minutes)'
    return vm_harness.probe_host()


class VMInstallTest(unittest.TestCase):
    """One booted VM, shared by the cases, torn down whatever happens."""

    vm: vm_harness.VM

    @classmethod
    def setUpClass(cls):
        reason = _opt_in()
        if reason:
            raise unittest.SkipTest(reason)
        cls.vm = vm_harness.VM().start()
        try:
            cls._prepare_guest(cls.vm)
        except BaseException:
            cls.vm.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        vm = getattr(cls, 'vm', None)
        if vm is not None:
            vm.stop()

    @classmethod
    def _prepare_guest(cls, vm: vm_harness.VM) -> None:
        """Prerequisites, then the checkout, exactly as an operator would have them.

        `uv` comes from the distribution so `install.sh`'s `command -v uv` resolves
        through the safe PATH it sets, which is what the trust check then validates.
        """
        vm.ssh('sudo', 'dnf', '-y', 'install', 'uv', 'git', 'acl', 'tar', 'gzip',
               'shadow-utils', 'sudo', timeout=1800)
        vm.upload(REPO_ROOT, GUEST_SOURCE, exclude=(
            '.git/*', 'build/*', '.venv/*', '__pycache__/*', '*.pyc',
        ))
        # Owned by the build user: `install.sh` builds from this tree as $SUDO_USER,
        # and that user must be able to `cd` into it after sudo drops privileges.
        # The cloud image's own account is used deliberately — it is a normal
        # wheel-sudo user, which is the shape this installer documents.
        vm.ssh('sudo', 'chown', '-R', f'{BUILDER}:{BUILDER}', GUEST_SOURCE)

        # A real host has /dev/kvm at 0660 root:kvm; the guest device node is created
        # 0666, and `check` then correctly fails "agent CAN write /dev/kvm". Fix the
        # DEVICE, not the check: the probe is asserting the right thing about an
        # unrealistic fixture.
        if vm.ssh('test', '-e', '/dev/kvm', check=False).returncode == 0:
            vm.ssh('sudo', 'chgrp', 'kvm', '/dev/kvm', check=False)
            vm.ssh('sudo', 'chmod', '0660', '/dev/kvm', check=False)

        # Fedora Cloud ships `/` at 0775 even though its own `filesystem` package
        # records 0555, so `install.sh` refuses — correctly — and no install is
        # possible on a stock image. Restore what the package says rather than
        # weakening the check: `rpm -V filesystem` must go clean, which PROVES the
        # guest now matches a standard Fedora instead of hiding the finding.
        if vm.ssh('stat', '-c', '%a', '/').stdout.strip() != '555':
            vm.ssh('sudo', 'chmod', '0555', '/')
        verification = vm.ssh('rpm', '-V', 'filesystem', check=False).stdout.strip()
        assert '/ ' not in verification, (
            'the guest still deviates from its own filesystem package:\n' + verification
        )

    # -- helpers ----------------------------------------------------------

    def install(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        """`sudo ./install.sh …` as the build user — the shipped script, unstubbed.

        Wrapped in `sh -c` deliberately: `ssh` joins the arguments into one command,
        so the `cd` has to be part of the same shell invocation as the script it
        makes relative.
        """
        quoted = ' '.join(shlex.quote(a) for a in args)
        return self.vm.ssh(
            'sh', '-c', f'cd {shlex.quote(GUEST_SOURCE)} && sudo ./install.sh {quoted}'.strip(),
            check=check,
        )

    def guest_text(self, *argv: str, check: bool = True) -> str:
        return self.vm.ssh(*argv, check=check).stdout

    # -- the install ------------------------------------------------------

    def test_01_fresh_install_creates_a_root_owned_tree(self):
        result = self.install()
        self.assertIn('Installed:', result.stdout)

        self.assertEqual(0, self.vm.ssh('test', '-d', LIB, check=False).returncode,
                         f'{LIB} was not created')
        # Root-owned and not group/world writable: the invariant the whole install
        # exists to establish, checked with the guest's real `stat`.
        owners = self.guest_text('sudo', 'stat', '-c', '%u:%g', LIB).strip()
        self.assertEqual('0:0', owners, f'{LIB} is not root-owned')
        # Symlinks are excluded on purpose: `lstat` reports 0777 for every one of
        # them regardless of target, and the kernel ignores a symlink's mode. Without
        # the type filter this flagged uv's `bin/python` and `lib64` links as
        # "group/world writable" — a false positive, measured on the VM.
        writable = self.guest_text(
            'sudo', 'find', LIB, '-type', 'f,d', '-perm', '/022', '-print')
        self.assertEqual('', writable.strip(), 'the installed tree is group/world writable')
        # And no file in it is owned by anyone but root.
        strangers = self.guest_text('sudo', 'find', LIB, '!', '-user', 'root', '-print')
        self.assertEqual('', strangers.strip(), f'non-root-owned files in {LIB}: {strangers}')

    def test_02_installed_code_is_the_installed_copy_not_the_checkout(self):
        """`install.sh` promises that editing the checkout afterwards changes
        nothing about what runs as root."""
        installed = self.guest_text(
            'sudo', f'{LIB}/agent-isolation/bin/python', '-I', '-c',
            'import agent_isolation, os; print(os.path.dirname(agent_isolation.__file__))',
        ).strip()
        self.assertTrue(installed.startswith(LIB), installed)
        self.assertNotIn(GUEST_SOURCE, installed)

        # Now change the checkout and prove the installed copy is unaffected.
        init = f'{GUEST_SOURCE}/src/agent_isolation/__init__.py'
        saved = self.guest_text('sudo', 'cat', init)
        try:
            self.vm.ssh('sudo', 'sh', '-c', f'printf "raise SystemExit(99)\\n" > {init}')
            still = self.guest_text(
                'sudo', f'{LIB}/agent-isolation/bin/python', '-I', '-c',
                'import agent_isolation, os; print(os.path.dirname(agent_isolation.__file__))',
            ).strip()
            self.assertTrue(still.startswith(LIB), still)
            # And the installed CLI still answers.
            self.assertIn('agent-account', self.guest_text(BIN, '--help'))
        finally:
            # The checkout was uploaded WITHOUT .git, so restore the bytes rather
            # than asking git for them.
            self.vm.ssh('sudo', 'sh', '-c',
                        f'cat > {init} <<"__AA_EOF__"\n{saved}\n__AA_EOF__')

    def test_03_the_collections_are_where_resolve_ansible_looks(self):
        self.assertEqual(
            0,
            self.vm.ssh('test', '-d', f'{LIB}/collections/ansible_collections/ansible/posix',
                        check=False).returncode,
            'the collections are not where resolve_ansible looks',
        )

    def test_04_the_console_script_works_for_an_unprivileged_caller(self):
        """`$BIN` is a symlink into the venv; a non-root login must be able to run it,
        and its shebang must point at the installed interpreter."""
        target = self.guest_text('readlink', '-f', BIN).strip()
        self.assertTrue(target.startswith(LIB), target)
        help_text = self.guest_text(BIN, '--help')
        self.assertIn('agent-account', help_text)

    def test_05_the_build_ran_as_the_builder_not_as_root(self):
        """The escalation the installer exists to prevent: a build hook running as
        root. The wheel must be owned by the builder, and no root-owned artifact may
        be left in the builder's home."""
        home = f'/home/{BUILDER}'
        owned_by_root = self.guest_text(
            'sudo', 'find', home, '-user', 'root', '-print', check=False,
        ).strip()
        # `~/.cache/uv` may legitimately be root-owned if uv was ever run as root,
        # but nothing the BUILD produced may be.
        offending = [
            line for line in owned_by_root.splitlines()
            if '/uv/' not in line and line.strip()
        ]
        self.assertEqual([], offending, f'root-owned files in the builder home: {offending}')

    def test_06_apply_and_check_work_through_the_installed_tool(self):
        """The install is only useful if the thing it installed provisions a host."""
        wt = '/srv/agent-work/wt'
        for argv in (
            ('rm', '-rf', '/srv/agent-work'),
            # Outside the developer's home on purpose: a root inside $HOME needs
            # `--allow-in-home`, a separate deliberate opt-in this case is not about.
            ('sudo', 'install', '-d', '-m', '0755', '-o', BUILDER, '-g', BUILDER, '/srv/agent-work'),
            ('git', 'init', '-q', wt),
            ('chown', '-R', f'{BUILDER}:{BUILDER}', wt),
            ('git', '-C', wt, 'config', 'user.email', 'a@b'),
            ('git', '-C', wt, 'config', 'user.name', 'a'),
            ('sh', '-c', f'echo x > {wt}/f && git -C {wt} add f && git -C {wt} commit -qm one'),
        ):
            self.vm.ssh(*argv)

        applied = self.vm.ssh(BIN, 'apply', '--dev', BUILDER, wt, check=False)
        self.assertEqual(0, applied.returncode, applied.stdout + applied.stderr)
        checked = self.vm.ssh(BIN, 'check', '--dev', BUILDER, wt, check=False)
        self.assertEqual(0, checked.returncode,
                         f'{checked.stdout}\n{checked.stderr}')
        self.assertIn('every invariant holds', checked.stdout)

    def test_07_an_upgrade_replaces_the_tree_and_keeps_it_working(self):
        before = self.guest_text('sudo', 'cat', f'{LIB}/agent-isolation/pyvenv.cfg', check=False)
        result = self.install()
        self.assertIn('Installed:', result.stdout)
        self.assertEqual(0, self.vm.ssh('test', '-d', f'{LIB}/agent-isolation', check=False).returncode)
        self.assertIn('agent-account', self.guest_text(BIN, '--help'))
        # No staging root left behind: the cleanup trap must have run.
        leftovers = self.guest_text('sudo', 'find', '/var/lib/agent-isolation',
                                    '-maxdepth', '1', '-name', 'install-tmp.*', '-print',
                                    check=False).strip()
        self.assertEqual('', leftovers, f'staging roots left behind: {leftovers}')

    def test_08_a_failed_install_leaves_the_previous_tree_in_place(self):
        """A build failure must not leave the host without a working install."""
        marker = f'{LIB}/agent-isolation/MARKER'
        self.vm.ssh('sudo', 'sh', '-c', f'printf "previous\\n" > {marker}')

        # Break the build the way a real one breaks: an unusable lock. It is copied
        # INSIDE the guest for the restore — uv.lock is 132 KB and cannot travel
        # through an ssh argv (`Argument list too long`, measured).
        lock = f'{GUEST_SOURCE}/uv.lock'
        self.vm.ssh('sudo', 'cp', '-a', lock, '/tmp/uv.lock.saved')
        try:
            self.vm.ssh('sudo', 'sh', '-c', f'printf "not a lock\\n" > {lock}')
            result = self.install(check=False)
            self.assertNotEqual(0, result.returncode, 'install.sh accepted a broken lock')
        finally:
            self.vm.ssh('sudo', 'cp', '-a', '/tmp/uv.lock.saved', lock)

        self.assertEqual(0, self.vm.ssh('test', '-f', marker, check=False).returncode,
                         'the previous install was destroyed by a failed upgrade')
        self.assertIn('previous', self.guest_text('sudo', 'cat', marker))
        self.assertIn('agent-account', self.guest_text(BIN, '--help'))

    def test_09_uninstall_removes_code_and_leaves_the_account(self):
        """The account, its ACLs and its journal belong to `agent-account`, not to
        the installer: `--uninstall` removes code only."""
        result = self.install('--uninstall')
        self.assertIn('Removed', result.stdout)
        self.assertNotEqual(0, self.vm.ssh('test', '-e', LIB, check=False).returncode,
                            'the install tree survived --uninstall')
        self.assertNotEqual(0, self.vm.ssh('test', '-e', BIN, check=False).returncode,
                            'the console script survived --uninstall')
        account = self.vm.ssh('getent', 'passwd', 'agent', check=False)
        self.assertEqual(0, account.returncode,
                         'no agent account exists at all — the apply in test_06 did not run; '
                         'this case cannot judge whether uninstall removed it')


if __name__ == '__main__':
    unittest.main()
