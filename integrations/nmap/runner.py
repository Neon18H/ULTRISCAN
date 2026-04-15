import ipaddress
import re
import subprocess
from dataclasses import dataclass

from .parser import NmapXmlParser, ParsedNmapOutput


@dataclass
class NmapRunResult:
    command: str
    raw_xml: str
    parsed: ParsedNmapOutput


class NmapRunner:
    base_binary = 'nmap'

    def run(self, target: str, version_detection: bool = True) -> NmapRunResult:
        self._validate_target(target)
        cmd = [self.base_binary, '-Pn', '-oX', '-']
        if version_detection:
            cmd.append('-sV')
        cmd.append(target)
        done = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120)
        parsed = NmapXmlParser().parse(done.stdout)
        return NmapRunResult(command=' '.join(cmd), raw_xml=done.stdout, parsed=parsed)

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
        raise ValueError('Target inválido o no autorizado')
