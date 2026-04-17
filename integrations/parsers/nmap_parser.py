from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree as ET


@dataclass
class ParsedPortScript:
    script_id: str
    output: str


@dataclass
class ParsedService:
    port: int
    protocol: str
    state: str
    service: str = ''
    product: str = ''
    version: str = ''
    extrainfo: str = ''
    cpe: str = ''
    banner: str = ''
    scripts: list[ParsedPortScript] = field(default_factory=list)

    def model_dump(self) -> dict[str, Any]:
        return {
            'port': self.port,
            'protocol': self.protocol,
            'state': self.state,
            'service': self.service,
            'product': self.product,
            'version': self.version,
            'extrainfo': self.extrainfo,
            'cpe': self.cpe,
            'banner': self.banner,
            'scripts': [vars(script) for script in self.scripts],
        }


@dataclass
class ParsedHost:
    host: str
    ip: str = ''
    state: str = 'unknown'
    ports: list[ParsedService] = field(default_factory=list)

    def model_dump(self) -> dict[str, Any]:
        return {
            'host': self.host,
            'ip': self.ip,
            'state': self.state,
            'ports': [port.model_dump() for port in self.ports],
        }


@dataclass
class ParsedNmapOutput:
    hosts: list[ParsedHost] = field(default_factory=list)


class NmapXmlParser:
    SAFE_SCRIPT_PREFIXES = ('http-', 'ssl-', 'ftp-', 'banner', 'ssh-', 'vuln', 'smb-', 'mysql-', 'rdp-')

    def parse(self, xml_content: str) -> ParsedNmapOutput:
        root = ET.fromstring(xml_content)
        parsed_hosts: list[ParsedHost] = []

        for host_node in root.findall('host'):
            primary_address = host_node.find("address[@addrtype='ipv4']") or host_node.find('address')
            hostname_node = host_node.find('./hostnames/hostname')
            host_state_node = host_node.find('status')

            ip = primary_address.attrib.get('addr', '') if primary_address is not None else ''
            host_label = hostname_node.attrib.get('name', '') if hostname_node is not None else ip
            parsed_host = ParsedHost(
                host=host_label or ip or 'unknown',
                ip=ip,
                state=host_state_node.attrib.get('state', 'unknown') if host_state_node is not None else 'unknown',
            )

            for port_node in host_node.findall('./ports/port'):
                state_node = port_node.find('state')
                service_node = port_node.find('service')
                scripts: list[ParsedPortScript] = []

                for script_node in port_node.findall('script'):
                    script_id = script_node.attrib.get('id', '')
                    output = script_node.attrib.get('output', '')
                    if script_id and (script_id.startswith(self.SAFE_SCRIPT_PREFIXES) or script_id == 'vulners'):
                        scripts.append(ParsedPortScript(script_id=script_id, output=output))

                extrainfo = service_node.attrib.get('extrainfo', '') if service_node is not None else ''
                tunnel = service_node.attrib.get('tunnel', '') if service_node is not None else ''
                banner = f"{extrainfo} {tunnel}".strip()

                parsed_host.ports.append(
                    ParsedService(
                        port=int(port_node.attrib.get('portid', 0)),
                        protocol=port_node.attrib.get('protocol', 'tcp'),
                        state=state_node.attrib.get('state', 'unknown') if state_node is not None else 'unknown',
                        service=service_node.attrib.get('name', '') if service_node is not None else '',
                        product=service_node.attrib.get('product', '') if service_node is not None else '',
                        version=service_node.attrib.get('version', '') if service_node is not None else '',
                        extrainfo=extrainfo,
                        cpe=service_node.attrib.get('cpe', '') if service_node is not None else '',
                        banner=banner,
                        scripts=scripts,
                    )
                )

            parsed_hosts.append(parsed_host)

        return ParsedNmapOutput(hosts=parsed_hosts)
