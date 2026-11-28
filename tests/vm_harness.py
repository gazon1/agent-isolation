"""A real, booted VM for tests that need root and a package manager.

`InstallScriptIntegrationTest` runs `install.sh` inside a user namespace with root
operations shimmed, because a test process may not write `/usr/local`. That covers
the shell logic, but it cannot cover what the real installer depends on being true:
a genuine `chown` reaching root ownership, `runuser` actually dropping privileges,
`uv` resolving the lock over the network, `ansible-galaxy` writing collections, and
the installed console script re-executing itself through `sudo`.

This module boots a Fedora Cloud image under KVM and gives a test an SSH handle to
it. Nothing is shimmed inside the guest: `sudo ./install.sh` runs the shipped
script as root exactly as an operator would.

Everything here is opt-in and cached:

* the image is downloaded once into `~/.cache/isolation-vm/`;
* each run gets a fresh qcow2 OVERLAY, so the cached base is never mutated;
* the VM is destroyed on teardown, including on failure.

The guest is reached over user-mode networking with a forwarded SSH port, so no
bridge, no libvirt, and no host network configuration is involved.
"""

import hashlib
import os
import pathlib
import shlex
import shutil
import socket
import subprocess
import tempfile
import time

#: Where a Cloud image is cached between runs.
CACHE_DIR = pathlib.Path(os.environ.get('AGENT_ISOLATION_VM_CACHE', '~/.cache/isolation-vm')).expanduser()

#: The default image: Fedora Cloud, which ships cloud-init, systemd and the
#: `fedora` user with NOPASSWD sudo — the three things a real install needs.
DEFAULT_IMAGE_URL = (
    'https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/'
    'Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2'
)

#: Expected digest of DEFAULT_IMAGE_URL, from the matching CHECKSUM file.
#:
#: Checked, not assumed. Measured while building this: an interrupted transfer
#: followed by a resume produced a file of exactly the right SIZE whose digest was
#: wrong, and `qemu-img check` then reported corrupt L2 entries. A download that is
#: only length-checked fails later, as a boot timeout, which reads as "the image is
#: fine and the test is flaky".
DEFAULT_IMAGE_SHA256 = '846574c8a97cd2d8dc1f231062d73107cc85cbbbda56335e264a46e3a6c8ab2f'
DEFAULT_IMAGE_SIZE = 583335936


class VMUnavailable(RuntimeError):
    """The host cannot provide a VM — reported as a skip, never as a failure."""


def _run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, check=False, **kwargs)


def probe_host() -> str:
    """Return "" when a VM can be booted here, else the reason it cannot."""
    if not os.path.exists('/dev/kvm'):
        return 'no /dev/kvm — a booted VM needs hardware virtualisation'
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        return '/dev/kvm is not readable and writable by this user'
    for tool in ('qemu-system-x86_64', 'qemu-img', 'genisoimage', 'ssh', 'ssh-keygen'):
        if shutil.which(tool) is None:
            return f'{tool} is not installed'
    return ''


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def _digest(path: pathlib.Path) -> str:
    hasher = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def _image_path() -> pathlib.Path:
    """The cached base image, downloaded once if it is not there.

    An explicit path in `AGENT_ISOLATION_VM_IMAGE` wins and is never downloaded or
    digested: a caller pointing at a local qcow2 should not be surprised by network
    traffic, and they can opt into verification with
    `AGENT_ISOLATION_VM_IMAGE_SHA256`.
    """
    override = os.environ.get('AGENT_ISOLATION_VM_IMAGE')
    if override:
        path = pathlib.Path(override).expanduser()
        if not path.is_file():
            raise VMUnavailable(f'AGENT_ISOLATION_VM_IMAGE is not a file: {path}')
        expected = os.environ.get('AGENT_ISOLATION_VM_IMAGE_SHA256')
        if expected and _digest(path) != expected.lower():
            raise VMUnavailable(f'{path} does not match AGENT_ISOLATION_VM_IMAGE_SHA256')
        return path

    url = os.environ.get('AGENT_ISOLATION_VM_IMAGE_URL', DEFAULT_IMAGE_URL)
    expected = os.environ.get('AGENT_ISOLATION_VM_IMAGE_SHA256', DEFAULT_IMAGE_SHA256)
    if url != DEFAULT_IMAGE_URL:
        # A different image has a different digest; the caller must supply it.
        expected = os.environ.get('AGENT_ISOLATION_VM_IMAGE_SHA256', '')
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / pathlib.Path(url).name

    if path.is_file() and (not expected or _digest(path) == expected.lower()):
        return path
    if path.is_file():
        # Present but wrong: an interrupted download must not be reused.
        path.unlink()

    # Download beside the target and rename, so an interrupted transfer never looks
    # like a usable image on the next run.
    partial = path.with_suffix(path.suffix + '.part')
    result = _run([
        'curl', '-sSL', '--retry', '8', '--retry-all-errors', '--retry-delay', '5',
        '-o', str(partial), url,
    ], timeout=3600)
    if result.returncode != 0 or not partial.is_file():
        partial.unlink(missing_ok=True)
        raise VMUnavailable(f'cannot download the VM image from {url}: {result.stderr.strip()}')
    if expected:
        actual = _digest(partial)
        if actual != expected.lower():
            partial.unlink(missing_ok=True)
            raise VMUnavailable(
                f'the downloaded image from {url} is corrupt: sha256 {actual}, expected {expected}'
            )
    partial.rename(path)
    return path


class VM:
    """One booted guest. Use `start()`, then `ssh()`; `stop()` on teardown."""

    def __init__(self, *, cpus: int = 2, memory_mb: int = 3072, boot_timeout: int = 300,
                 workdir: pathlib.Path | None = None):
        self.cpus = cpus
        self.memory_mb = memory_mb
        self.boot_timeout = boot_timeout
        self._owned_tmp = workdir is None
        self.workdir = pathlib.Path(workdir or tempfile.mkdtemp(prefix='aa-vm-'))
        self._process = None
        self.console = self.workdir / 'console.log'
        self.port = _free_port()
        self.user = 'fedora'

    # -- lifecycle --------------------------------------------------------

    def __enter__(self) -> 'VM':
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()

    def start(self) -> 'VM':
        reason = probe_host()
        if reason:
            raise VMUnavailable(reason)
        base = _image_path()
        overlay = self.workdir / 'disk.qcow2'
        created = _run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2',
                        '-b', str(base), str(overlay)])
        if created.returncode != 0:
            raise VMUnavailable(f'cannot create the disk overlay: {created.stderr.strip()}')

        seed = self._seed_iso()
        argv = [
            'qemu-system-x86_64',
            '-machine', 'accel=kvm', '-cpu', 'host',
            '-smp', str(self.cpus), '-m', str(self.memory_mb),
            '-drive', f'file={overlay},if=virtio,format=qcow2,cache=unsafe',
            '-drive', f'file={seed},if=virtio,format=raw,readonly=on',
            '-netdev', f'user,id=n0,hostfwd=tcp:127.0.0.1:{self.port}-:22',
            '-device', 'virtio-net-pci,netdev=n0',
            '-display', 'none',
            '-serial', f'file:{self.console}',
            '-pidfile', str(self.workdir / 'qemu.pid'),
            '-daemonize',
        ]
        started = _run(argv)
        if started.returncode != 0:
            raise VMUnavailable(f'qemu refused to start: {started.stderr.strip()}')
        self._process = int((self.workdir / 'qemu.pid').read_text().strip())
        self._wait_for_ssh()
        return self

    def stop(self) -> None:
        if self._process is not None:
            # A clean poweroff first: an abrupt kill can leave the overlay with a
            # dirty journal, which makes a failure look like an image problem.
            _run(self._ssh_argv() + ['sudo', 'poweroff'], timeout=30)
            deadline = time.time() + 30
            while time.time() < deadline:
                if _run(['kill', '-0', str(self._process)]).returncode != 0:
                    break
                time.sleep(1)
            _run(['kill', '-9', str(self._process)])
            self._process = None
        if self._owned_tmp:
            shutil.rmtree(self.workdir, ignore_errors=True)

    # -- access -----------------------------------------------------------

    def _seed_iso(self) -> pathlib.Path:
        """cloud-init NoCloud seed: the test's key, and passwordless sudo."""
        key = self.workdir / 'id_ed25519'
        generated = _run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)])
        if generated.returncode != 0:
            raise VMUnavailable(f'cannot generate an SSH key: {generated.stderr.strip()}')
        public = key.with_suffix('.pub').read_text(encoding='utf-8').strip()
        seed_dir = self.workdir / 'seed'
        seed_dir.mkdir()
        (seed_dir / 'meta-data').write_text(
            'instance-id: agent-isolation-test\nlocal-hostname: agent-isolation-vm\n',
            encoding='utf-8',
        )
        (seed_dir / 'user-data').write_text(
            '#cloud-config\n'
            'users:\n'
            f'  - name: {self.user}\n'
            '    groups: wheel\n'
            '    lock_passwd: true\n'
            '    sudo: "ALL=(ALL) NOPASSWD:ALL"\n'
            '    shell: /bin/bash\n'
            '    ssh_authorized_keys:\n'
            f'      - {public}\n'
            'ssh_pwauth: false\n'
            'disable_root: true\n'
            + ('' if os.environ.get('AA_VM_NO_RESIZE') else
               'growpart:\n'
               '  mode: auto\n'
               '  devices: ["/"]\n'
               'resize_rootfs: true\n'),
            encoding='utf-8',
        )
        iso = self.workdir / 'seed.iso'
        built = _run(['genisoimage', '-quiet', '-output', str(iso), '-volid', 'cidata',
                      '-joliet', '-rock', str(seed_dir / 'user-data'), str(seed_dir / 'meta-data')])
        if built.returncode != 0:
            raise VMUnavailable(f'cannot build the cloud-init seed: {built.stderr.strip()}')
        return iso

    def _ssh_argv(self) -> list[str]:
        return [
            'ssh', '-p', str(self.port),
            '-i', str(self.workdir / 'id_ed25519'),
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR',
            '-o', 'IdentitiesOnly=yes',
            '-o', 'ConnectTimeout=10',
            f'{self.user}@127.0.0.1',
        ]

    def _wait_for_ssh(self) -> None:
        deadline = time.time() + self.boot_timeout
        while time.time() < deadline:
            probe = _run(self._ssh_argv() + ['true'], timeout=15)
            if probe.returncode == 0:
                # cloud-init may still be finishing; `--wait` makes the first
                # command deterministic rather than racing the seed.
                _run(self._ssh_argv() + ['sudo', 'cloud-init', 'status', '--wait'], timeout=300)
                return
            if self._process is not None and _run(['kill', '-0', str(self._process)]).returncode != 0:
                break
            time.sleep(3)
        tail = ''
        if self.console.is_file():
            tail = '\n'.join(self.console.read_text(errors='replace').splitlines()[-25:])
        raise VMUnavailable(f'the VM did not become reachable in {self.boot_timeout}s\n{tail}')

    def ssh(self, *argv: str, timeout: int = 1800, check: bool = True) -> subprocess.CompletedProcess:
        """Run a command in the guest. `check` raises with the guest's own output.

        The arguments are joined and shell-QUOTED into one remote command. Passing
        them as separate ssh arguments would let ssh concatenate them unquoted, so
        `sh -c 'touch /tmp/x'` arrives as `sh -c touch /tmp/x` and the script half
        silently disappears — measured while building this suite.
        """
        remote = ' '.join(shlex.quote(a) for a in argv)
        result = _run(self._ssh_argv() + [remote], timeout=timeout)
        if check and result.returncode != 0:
            raise AssertionError(
                f'command failed in the VM ({result.returncode}): {remote}\n'
                f'--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}'
            )
        return result

    def upload(self, source: pathlib.Path, destination: str, *, exclude=()) -> None:
        """Copy a tree into the guest, skipping what a build does not need."""
        self.ssh('mkdir', '-p', destination)
        tar_argv = ['tar', '-C', str(source), '-cf', '-']
        tar_argv += [f'--exclude={pattern}' for pattern in exclude]
        tar_argv.append('.')
        scp_argv = [
            'ssh', '-p', str(self.port),
            '-i', str(self.workdir / 'id_ed25519'),
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR',
            '-o', 'IdentitiesOnly=yes',
            f'{self.user}@127.0.0.1',
            f'tar -C {destination} -xf -',
        ]
        producer = subprocess.Popen(tar_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        consumer = subprocess.run(scp_argv, stdin=producer.stdout,
                                  capture_output=True, text=True, check=False)
        producer.stdout.close()
        _, producer_err = producer.communicate()
        if producer.returncode != 0 or consumer.returncode != 0:
            raise AssertionError(
                f'cannot copy {source} into the VM: '
                f'{producer_err.decode(errors="replace")} {consumer.stderr}'
            )
