#!/usr/bin/python3
"""NEEBLES Secrets: strict desktop-user systemd installer (no switch).

This module-owned tool installs an *ordinary* user unit, not a symlink,
so the current Boss uninstall.extras contract can stop and retire it.
It deliberately does not install KeePassXC on the host or create vaults.

IMPORTANT: a manual execution of this helper is not Lifecycle automation.
A future governed desktop-session install authority must invoke this
helper as part of Boss Install, without bypassing sandbox boundaries.
"""
from __future__ import annotations
import argparse
import json
import os
import socket
import stat
import struct
import subprocess
import tempfile
import time
from pathlib import Path

MODULE = 'neebles-secrets'
SERVICE = 'neebles-neebles-secrets-daemon.service'
INSTALLED = Path('/opt/neebles/modules/neebles-secrets')
MANIFEST = INSTALLED / 'manifest.json'
SOURCE = INSTALLED / 'integration/systemd-user' / SERVICE
EXPECTED_EXEC = '/opt/neebles/modules/neebles-secrets/runtime/neebles-secrets --serve'
# Mirrors the installed F29 source exactly: never install arbitrary unit content.
EXPECTED_UNIT = f'''[Unit]
Description=NEEBLES Secrets independent user vault daemon
After=basic.target
ConditionPathExists=/opt/neebles/modules/neebles-secrets/manifest.json

[Service]
Type=simple
ExecStart={EXPECTED_EXEC}
Restart=on-failure
RestartSec=2
UMask=0077
NoNewPrivileges=true

[Install]
WantedBy=default.target
'''


def require_real_file(path: Path) -> bytes:
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o002:
        raise RuntimeError(f'unsafe file type/mode: {path}')
    return path.read_bytes()


def verified_installed() -> bytes:
    """Do not trust arbitrary systemd snippets from an unverified path."""
    manifest = json.loads(require_real_file(MANIFEST))
    if (manifest.get('schema') != 4 or manifest.get('name') != MODULE
            or manifest.get('entrypoint') != 'runtime/neebles-secrets-ui'):
        raise RuntimeError('installed Secrets module manifest identity mismatch')
    extras = manifest.get('uninstall', {}).get('extras', [])
    expected = [item for item in extras if item.get('id') == 'secrets-daemon']
    if len(expected) != 1 or expected[0].get('type') != 'service' \
            or expected[0].get('provider') != 'systemd-user' \
            or expected[0].get('exec_start') != EXPECTED_EXEC \
            or manifest['uninstall'].get('hardcoded', {}).get('session_service') != SERVICE \
            or expected[0].get('name') != '$hardcoded.session_service':
        raise RuntimeError('Boss uninstall contract for Secrets daemon is missing or invalid')
    unit = require_real_file(SOURCE)
    if unit != EXPECTED_UNIT.encode('utf-8'):
        raise RuntimeError('installed Secrets systemd unit differs from the certified F29 layout')
    binary = INSTALLED / 'runtime/neebles-secrets'
    bm = binary.lstat()
    if not stat.S_ISREG(bm.st_mode) or not bm.st_mode & 0o111:
        raise RuntimeError('Secrets daemon binary missing or not executable')
    return unit


def check_desktop_user() -> tuple[Path, Path]:
    uid = os.getuid()
    if uid == 0 or os.geteuid() == 0 or uid != os.geteuid():
        raise RuntimeError('run as desktop user WITHOUT sudo')
    home = Path.home()
    hm = home.lstat()
    if not stat.S_ISDIR(hm.st_mode) or hm.st_uid != uid:
        raise RuntimeError('desktop HOME not owned / is symlink')
    runtime = os.environ.get('XDG_RUNTIME_DIR')
    if not runtime:
        raise RuntimeError('no XDG_RUNTIME_DIR for the desktop session')
    rp = Path(runtime)
    rm = rp.lstat()
    if not rp.is_absolute() or not stat.S_ISDIR(rm.st_mode) or rm.st_uid != uid \
            or stat.S_IMODE(rm.st_mode) & 0o077:
        raise RuntimeError('unsafe desktop runtime directory')
    return home, rp


def directory_chain(home: Path) -> Path:
    path = home
    for part in ('.config', 'systemd', 'user'):
        path = path / part
        if path.is_symlink():
            raise RuntimeError(f'refusing symlink directory: {path}')
        if path.exists():
            m = path.lstat()
            if not stat.S_ISDIR(m.st_mode) or m.st_uid != os.getuid() or m.st_mode & 0o002:
                raise RuntimeError(f'unsafe systemd directory: {path}')
        else:
            path.mkdir(mode=0o700)
    return path


def systemctl(*args: str) -> subprocess.CompletedProcess:
    p = subprocess.run(('/usr/bin/systemctl', '--user', *args),
                       text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=25, check=False)
    if p.returncode:
        raise RuntimeError(f'systemctl --user {" ".join(args)} failed: {p.stderr.strip()[:450]}')
    return p


def verify_socket(runtime: Path, timeout: float = 12.0) -> None:
    path = runtime / 'neebles-secrets' / 'secrets.sock'
    end = time.monotonic() + timeout
    error = 'not yet available'
    while time.monotonic() < end:
        try:
            m = path.lstat()
            if not stat.S_ISSOCK(m.st_mode) or m.st_uid != os.getuid() \
                    or stat.S_IMODE(m.st_mode) != 0o600:
                raise RuntimeError('socket is not user-owned mode 0600')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect(str(path))
                req = json.dumps({'op': 'vault.status'}).encode()
                sock.sendall(struct.pack('!I', len(req)) + req)
                header = read_exact(sock, 4)
                count, = struct.unpack('!I', header)
                if count < 1 or count > 16384:
                    raise RuntimeError('invalid Secrets IPC frame length')
                result = json.loads(read_exact(sock, count))
                data = result.get('data', {})
                if result.get('ok') is not True or data.get('service') != MODULE \
                        or data.get('installed') is not True:
                    raise RuntimeError('Secrets daemon status not healthy / not installed')
                # Intentionally do not require initialized or unlocked.
                return
        except (OSError, ValueError, TimeoutError, RuntimeError) as exc:
            error = str(exc)
            time.sleep(0.15)
    raise RuntimeError(f'Secrets service has not provided a healthy socket: {error}')


def read_exact(sock: socket.socket, count: int) -> bytes:
    out = bytearray()
    while len(out) < count:
        chunk = sock.recv(count - len(out))
        if not chunk:
            raise RuntimeError('truncated Secrets IPC frame')
        out.extend(chunk)
    return bytes(out)


def create_unit_once(path: Path, expected: bytes) -> bool:
    if path.is_symlink():
        raise RuntimeError(f'refusing symlink systemd unit: {path}')
    if path.exists():
        m = path.lstat()
        if not stat.S_ISREG(m.st_mode) or m.st_uid != os.getuid() or m.st_mode & 0o002:
            raise RuntimeError('existing user systemd unit is not owned safe regular file')
        if path.read_bytes() != expected:
            raise RuntimeError('existing unit differs: refusing silent override')
        return False
    fd, tempname = tempfile.mkstemp(prefix='.neebles-secrets-unit-', dir=path.parent)
    temp = Path(tempname)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(expected)
            f.flush()
            os.fsync(f.fileno())
        temp.chmod(0o600)
        os.link(temp, path)  # O_EXCL-like create; never overwrites
        return True
    finally:
        temp.unlink(missing_ok=True)


def install() -> None:
    home, runtime = check_desktop_user()
    unit_bytes = verified_installed()
    # The user manager is required; never fall back to a root manager.
    systemctl('show-environment')
    unit_path = directory_chain(home) / SERVICE
    created = create_unit_once(unit_path, unit_bytes)
    try:
        systemctl('daemon-reload')
        systemctl('enable', '--now', SERVICE)
        systemctl('is-active', '--quiet', SERVICE)
        verify_socket(runtime)
    except Exception:
        # Roll back only an *entirely new* unit, never destroy an old service.
        if created:
            try:
                systemctl('disable', '--now', SERVICE)
            except Exception:
                pass
            if not unit_path.is_symlink() and unit_path.is_file() \
                    and unit_path.read_bytes() == unit_bytes:
                unit_path.unlink()
            try:
                systemctl('daemon-reload')
            except Exception:
                pass
        raise
    print(f'GREEN: Secrets user service enabled: {SERVICE}')
    print(f'GREEN: authenticated socket: {runtime}/neebles-secrets/secrets.sock')
    print('GREEN: future user logins use default.target; NO SWITCH, NO MASTER VAULT CREATED')


def preview() -> None:
    expected = EXPECTED_UNIT
    assert f'ExecStart={EXPECTED_EXEC}' in expected
    assert 'WantedBy=default.target' in expected
    assert 'ConditionPathExists=' in expected
    assert SERVICE.startswith('neebles-neebles-secrets-')
    print('F31 SOURCE CHECK PASS / NO WRITES')
    print('Target user unit:', Path.home()/'.config/systemd/user'/SERVICE)
    print('ExecStart:', EXPECTED_EXEC)
    print('Lifecycle activation: NOT YET WIRED')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--check-source', action='store_true')
    modes.add_argument('--install', action='store_true')
    args = parser.parse_args()
    if args.check_source:
        preview()
    else:
        install()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, AssertionError) as e:
        raise SystemExit(f'F31 SERVICE BLOCKED: {e}') from e
