from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass
from typing import Any


RAW_SOCKET_ERROR_PATTERNS = (
    'couldn\'t open a raw socket',
    'operation not permitted',
    'requires root privileges',
    'you requested a scan type which requires root privileges',
)


@dataclass
class NmapRunResult:
    command: str
    return_code: int
    stdout: str
    stderr: str
    xml_output: str
    metadata: dict[str, Any]


class NmapRunner:
    base_binary = 'nmap'
    timeout_seconds = 240

    PROFILE_ARGS = {
        'discovery': ['-sT', '-Pn', '-n', '--unprivileged'],
        'full_tcp_safe': ['-sT', '-sV', '-Pn', '-n', '--unprivileged', '-p-'],
    }

    FALLBACK_PROFILE_ARGS = {
        'discovery': ['-sT', '-Pn', '-n', '--unprivileged'],
        'full_tcp_safe': ['-sT', '-sV', '-Pn', '-n', '--unprivileged'],
    }

    def run(self, target: str, profile: str) -> NmapRunResult:
        self._validate_target(target)
        if profile not in self.PROFILE_ARGS:
            raise ValueError(f'Perfil de escaneo no soportado por runner nmap: {profile}')

        primary_result = self._run_command(target=target, args=self.PROFILE_ARGS[profile], profile=profile, mode='primary')

        if primary_result.return_code == 0:
            return primary_result

        if not self._is_privilege_error(primary_result.stderr, primary_result.stdout):
            return primary_result

        fallback_args = self.FALLBACK_PROFILE_ARGS.get(profile)
        if not fallback_args:
            return primary_result

        fallback_result = self._run_command(target=target, args=fallback_args, profile=profile, mode='fallback_unprivileged')
        fallback_result.metadata['fallback_used'] = True
        fallback_result.metadata['fallback_reason'] = 'raw_socket_or_privilege_error'
        fallback_result.metadata['initial_command'] = primary_result.command
        fallback_result.metadata['initial_return_code'] = primary_result.return_code
        fallback_result.metadata['initial_stderr'] = primary_result.stderr
        fallback_result.metadata['initial_stdout'] = primary_result.stdout

        if fallback_result.return_code == 0:
            return fallback_result

        fallback_result.stderr = (
            f"Primary command failed due to privileges/raw socket and fallback also failed. "
            f"Primary stderr: {primary_result.stderr.strip()} | "
            f"Fallback stderr: {fallback_result.stderr.strip()}"
        )
        return fallback_result

    def _run_command(self, target: str, args: list[str], profile: str, mode: str) -> NmapRunResult:
        cmd = [self.base_binary, '-oX', '-', *args, target]
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        return NmapRunResult(
            command=' '.join(cmd),
            return_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            xml_output=completed.stdout,
            metadata={
                'profile': profile,
                'target': target,
                'timeout_seconds': self.timeout_seconds,
                'mode': mode,
                'fallback_used': False,
            },
        )

    def _is_privilege_error(self, stderr: str, stdout: str) -> bool:
        combined = f'{stderr}\n{stdout}'.lower()
        return any(pattern in combined for pattern in RAW_SOCKET_ERROR_PATTERNS)

    def _validate_target(self, target: str) -> None:
        if '/' in target:
            ipaddress.ip_network(target, strict=False)
            return
        try:
            ipaddress.ip_address(target)
            return
        except ValueError:
            pass

        if re.match(r'^(?!-)[A-Za-z0-9.-]{1,253}(?<!-)$', target):
            return

        raise ValueError('Target inválido o no autorizado para Nmap')
