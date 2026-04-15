from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass
from typing import Any


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
        'discovery': ['-sn', '-PS22,80,443', '-PA80,443', '--top-ports', '1000', '-sV'],
        'full_tcp_safe': ['-Pn', '-p-', '-sV', '--version-light', '--defeat-rst-ratelimit'],
    }

    def run(self, target: str, profile: str) -> NmapRunResult:
        self._validate_target(target)
        if profile not in self.PROFILE_ARGS:
            raise ValueError(f'Perfil de escaneo no soportado por runner nmap: {profile}')

        cmd = [self.base_binary, '-oX', '-', *self.PROFILE_ARGS[profile], target]
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
            },
        )

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
