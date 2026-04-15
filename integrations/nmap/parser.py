from dataclasses import dataclass, field
from typing import List
from xml.etree import ElementTree as ET


@dataclass
class ParsedService:
    port: int
    protocol: str
    state: str
    name: str = ''
    product: str = ''
    version: str = ''
    banner: str = ''


@dataclass
class ParsedHost:
    address: str
    services: List[ParsedService] = field(default_factory=list)

    def model_dump(self):
        return {'address': self.address, 'services': [svc.__dict__ for svc in self.services]}


@dataclass
class ParsedNmapOutput:
    hosts: List[ParsedHost]


class NmapXmlParser:
    def parse(self, xml_content: str) -> ParsedNmapOutput:
        root = ET.fromstring(xml_content)
        hosts: List[ParsedHost] = []
        for host in root.findall('host'):
            address = host.find('address')
            if address is None:
                continue
            parsed_host = ParsedHost(address=address.attrib.get('addr', 'unknown'))
            for port in host.findall('./ports/port'):
                state = port.find('state')
                service = port.find('service')
                parsed_host.services.append(
                    ParsedService(
                        port=int(port.attrib.get('portid', 0)),
                        protocol=port.attrib.get('protocol', 'tcp'),
                        state=state.attrib.get('state', 'unknown') if state is not None else 'unknown',
                        name=service.attrib.get('name', '') if service is not None else '',
                        product=service.attrib.get('product', '') if service is not None else '',
                        version=service.attrib.get('version', '') if service is not None else '',
                        banner=service.attrib.get('extrainfo', '') if service is not None else '',
                    )
                )
            hosts.append(parsed_host)
        return ParsedNmapOutput(hosts=hosts)
