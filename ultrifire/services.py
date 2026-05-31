import ipaddress
import json
import re
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone

POLICY_FILE_NAME = 'managed_policies.json'
LEGACY_RULE_FILE_NAME = 'managed_rules.json'
SUPPORTED_POLICY_TYPES = {'outbound_allow', 'inbound_publish', 'interzone', 'blocklist'}
PROTOCOLS = {'tcp', 'udp', 'icmp', 'any'}
TCP_UDP_PROTOCOLS = {'tcp', 'udp'}
ACTIONS = {'pass', 'block', 'reject'}
FQDN_RE = re.compile(r'^(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$')
ALIAS_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$')
INTERFACE_RE = re.compile(r'^[A-Za-z0-9_.:-]{1,64}$')


class PolicyValidationError(ValueError):
    pass


def _base_dir(organization=None) -> Path:
    slug = getattr(organization, 'slug', None) or 'default'
    return Path(settings.BASE_DIR) / 'var' / 'ultrifire' / slug


def managed_policies_path(organization=None) -> Path:
    return _base_dir(organization) / POLICY_FILE_NAME


def ensure_policy_store(organization=None) -> Path:
    path = managed_policies_path(organization)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        legacy = path.with_name(LEGACY_RULE_FILE_NAME)
        payload = {'policies': []}
        if legacy.exists():
            try:
                legacy_data = json.loads(legacy.read_text(encoding='utf-8'))
                payload['legacy_rules'] = legacy_data.get('rules', legacy_data)
            except json.JSONDecodeError:
                payload['legacy_rules'] = []
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
    return path


def load_managed_policies(organization=None) -> dict[str, Any]:
    path = ensure_policy_store(organization)
    try:
        data = json.loads(path.read_text(encoding='utf-8') or '{}')
    except json.JSONDecodeError:
        data = {'policies': []}
    if not isinstance(data, dict):
        data = {'policies': []}
    policies = data.get('policies')
    if not isinstance(policies, list):
        data['policies'] = []
    return data


def save_managed_policies(data: dict[str, Any], organization=None) -> None:
    path = ensure_policy_store(organization)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True), encoding='utf-8')


def list_policies(organization=None) -> list[dict[str, Any]]:
    return load_managed_policies(organization).get('policies', [])


def _is_any(value: Any) -> bool:
    return str(value).strip().lower() == 'any'


def validate_address(value: Any, *, allow_any=True, allow_fqdn=True, allow_alias=True, field='address') -> str:
    text = str(value or '').strip()
    if not text:
        raise PolicyValidationError(f'{field} es obligatorio.')
    if allow_any and _is_any(text):
        return 'any'
    try:
        if '/' in text:
            ipaddress.ip_network(text, strict=False)
        else:
            ipaddress.ip_address(text)
        return text
    except ValueError:
        pass
    if allow_fqdn and FQDN_RE.match(text):
        return text.lower()
    if allow_alias and ALIAS_RE.match(text):
        return text
    raise PolicyValidationError(f'{field} debe ser any, IP, CIDR, FQDN o alias válido.')


def validate_ip(value: Any, *, field='ip') -> str:
    text = str(value or '').strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise PolicyValidationError(f'{field} debe ser una IP válida.') from exc


def validate_interface(value: Any, *, field='interface') -> str:
    text = str(value or '').strip().lower()
    if not text or not INTERFACE_RE.match(text):
        raise PolicyValidationError(f'{field} debe ser una interfaz/zona válida.')
    return text


def validate_protocol(value: Any, *, allowed=PROTOCOLS) -> str:
    protocol = str(value or '').strip().lower()
    if protocol not in allowed:
        raise PolicyValidationError(f'protocol debe ser uno de: {", ".join(sorted(allowed))}.')
    return protocol


def validate_port(value: Any, *, field='destination_port', allow_any=True) -> str:
    text = str(value or '').strip().lower()
    if allow_any and text == 'any':
        return 'any'
    def valid_int(part: str) -> bool:
        return part.isdigit() and 1 <= int(part) <= 65535
    if '-' in text:
        start, end = text.split('-', 1)
        if valid_int(start) and valid_int(end) and int(start) <= int(end):
            return f'{int(start)}-{int(end)}'
    elif valid_int(text):
        return str(int(text))
    raise PolicyValidationError(f'{field} debe ser any, un puerto 1-65535 o un rango válido.')


def normalize_allowed_sources(value: Any) -> list[str]:
    if value in (None, '', []):
        return ['any']
    if isinstance(value, str):
        items = [item.strip() for item in re.split(r'[\n,]+', value) if item.strip()]
    elif isinstance(value, list):
        items = value
    else:
        raise PolicyValidationError('allowed_sources debe ser una lista o texto separado por comas.')
    if not items:
        return ['any']
    normalized = [validate_address(item, allow_fqdn=False, allow_alias=False, field='allowed_sources') for item in items]
    if 'any' in normalized and len(normalized) > 1:
        raise PolicyValidationError('allowed_sources no puede mezclar any con CIDRs/IPs específicos.')
    return normalized


def _base_policy(payload: dict[str, Any]) -> dict[str, Any]:
    policy_type = str(payload.get('policy_type', '')).strip().lower()
    if policy_type not in SUPPORTED_POLICY_TYPES:
        raise PolicyValidationError('policy_type no soportado.')
    name = str(payload.get('name') or '').strip()
    if not name:
        raise PolicyValidationError('name es obligatorio.')
    return {
        'id': str(payload.get('id') or uuid.uuid4()),
        'name': name,
        'enabled': bool(payload.get('enabled', True)),
        'policy_type': policy_type,
        'description': str(payload.get('description') or payload.get('reason') or '').strip(),
        'managed_by': 'ultrifire',
        'created_at': payload.get('created_at') or timezone.now().isoformat(),
    }


def validate_policy(payload: dict[str, Any]) -> dict[str, Any]:
    policy = _base_policy(payload)
    policy_type = policy['policy_type']
    if policy_type == 'outbound_allow':
        policy.update({
            'inbound_interface': validate_interface(payload.get('inbound_interface', 'lan'), field='inbound_interface'),
            'source': validate_address(payload.get('source'), field='source'),
            'destination': validate_address(payload.get('destination', 'any'), field='destination'),
            'protocol': validate_protocol(payload.get('protocol', 'any')),
            'destination_port': validate_port(payload.get('destination_port', 'any')),
            'schedule': str(payload.get('schedule') or '').strip(),
            'action': 'pass',
        })
    elif policy_type == 'inbound_publish':
        provider = str(payload.get('provider') or 'other').strip().lower()
        cloud_resource = deepcopy(payload.get('cloud_resource') or {})
        if cloud_resource and not isinstance(cloud_resource, dict):
            raise PolicyValidationError('cloud_resource debe ser un objeto JSON.')
        policy.update({
            'provider': provider,
            'cloud_resource': cloud_resource,
            'inbound_interface': validate_interface(payload.get('inbound_interface', 'wan'), field='inbound_interface'),
            'public_address': validate_address(payload.get('public_address', 'wan_address'), allow_any=False, allow_fqdn=False, allow_alias=True, field='public_address'),
            'public_port': validate_port(payload.get('public_port'), field='public_port', allow_any=False),
            'backend_ip': validate_ip(payload.get('backend_ip'), field='backend_ip'),
            'backend_port': validate_port(payload.get('backend_port'), field='backend_port', allow_any=False),
            'protocol': validate_protocol(payload.get('protocol', 'tcp'), allowed=TCP_UDP_PROTOCOLS),
            'allowed_sources': normalize_allowed_sources(payload.get('allowed_sources', ['any'])),
            'nat_enabled': bool(payload.get('nat_enabled', True)),
            'create_firewall_pass_rule': bool(payload.get('create_firewall_pass_rule', True)),
        })
    elif policy_type == 'interzone':
        policy.update({
            'source_zone': validate_interface(payload.get('source_zone') or payload.get('source_interface'), field='source_zone'),
            'destination_zone': validate_interface(payload.get('destination_zone') or payload.get('destination_interface'), field='destination_zone'),
            'source': validate_address(payload.get('source'), field='source'),
            'destination': validate_address(payload.get('destination'), field='destination'),
            'protocol': validate_protocol(payload.get('protocol', 'any')),
            'destination_port': validate_port(payload.get('destination_port', 'any')),
            'action': str(payload.get('action', 'pass')).strip().lower(),
        })
        if policy['action'] not in ACTIONS:
            raise PolicyValidationError('action debe ser pass, block o reject.')
    elif policy_type == 'blocklist':
        policy.update({
            'inbound_interface': validate_interface(payload.get('inbound_interface'), field='inbound_interface'),
            'source': validate_address(payload.get('source', 'any'), field='source'),
            'destination': validate_address(payload.get('destination', 'any'), field='destination'),
            'protocol': validate_protocol(payload.get('protocol', 'any')),
            'reason': str(payload.get('reason') or payload.get('description') or '').strip(),
            'action': 'block',
        })
    return policy


def create_policy(payload: dict[str, Any], *, organization=None, safe_mode=True) -> dict[str, Any]:
    policy = validate_policy(payload)
    data = load_managed_policies(organization)
    data.setdefault('policies', []).append(policy)
    save_managed_policies(data, organization)
    return {'ok': True, 'safe_mode': bool(safe_mode), 'applied': False, 'policy': policy}


def disable_policy(policy_id: str, *, organization=None) -> dict[str, Any]:
    data = load_managed_policies(organization)
    for policy in data.get('policies', []):
        if policy.get('id') == policy_id:
            policy['enabled'] = False
            policy['disabled_at'] = timezone.now().isoformat()
            save_managed_policies(data, organization)
            return {'ok': True, 'policy': policy}
    raise PolicyValidationError('Política gestionada no encontrada.')


def get_policy(policy_id: str, *, organization=None) -> dict[str, Any]:
    for policy in list_policies(organization):
        if policy.get('id') == policy_id:
            return policy
    raise PolicyValidationError('Política gestionada no encontrada.')


def preview_policy(policy: dict[str, Any]) -> dict[str, Any]:
    policy_type = policy.get('policy_type')
    risks = []
    firewall_rule = None
    nat = None
    equivalent = []
    if policy_type == 'outbound_allow':
        firewall_rule = {
            'interface': policy['inbound_interface'],
            'action': 'pass',
            'source': policy['source'],
            'destination': policy['destination'],
            'protocol': policy['protocol'],
            'destination_port': policy['destination_port'],
        }
        equivalent.append(f"pass in on {policy['inbound_interface']} proto {policy['protocol']} from {policy['source']} to {policy['destination']} port {policy['destination_port']}")
    elif policy_type == 'inbound_publish':
        nat = {
            'type': 'port_forward',
            'interface': policy['inbound_interface'],
            'public_address': policy['public_address'],
            'public_port': policy['public_port'],
            'backend_ip': policy['backend_ip'],
            'backend_port': policy['backend_port'],
            'protocol': policy['protocol'],
        }
        firewall_rule = {
            'interface': policy['inbound_interface'],
            'action': 'pass',
            'source': policy['allowed_sources'],
            'destination': policy['backend_ip'],
            'protocol': policy['protocol'],
            'destination_port': policy['backend_port'],
        }
        equivalent.append(f"rdr on {policy['inbound_interface']} proto {policy['protocol']} from {policy['allowed_sources']} to {policy['public_address']} port {policy['public_port']} -> {policy['backend_ip']} port {policy['backend_port']}")
        if policy['allowed_sources'] == ['any']:
            risks.append('El servicio queda publicado para cualquier origen en Internet.')
        if policy.get('create_firewall_pass_rule'):
            risks.append('Se requiere regla pass asociada; mantenerla acotada al backend y puerto definidos.')
    elif policy_type == 'interzone':
        firewall_rule = {
            'interface': policy['source_zone'],
            'action': policy['action'],
            'source': policy['source'],
            'destination': policy['destination'],
            'protocol': policy['protocol'],
            'destination_port': policy['destination_port'],
            'to_zone': policy['destination_zone'],
        }
        equivalent.append(f"{policy['action']} in on {policy['source_zone']} proto {policy['protocol']} from {policy['source']} to {policy['destination']} port {policy['destination_port']}")
    elif policy_type == 'blocklist':
        firewall_rule = {
            'interface': policy['inbound_interface'],
            'action': 'block',
            'source': policy['source'],
            'destination': policy['destination'],
            'protocol': policy['protocol'],
        }
        equivalent.append(f"block in on {policy['inbound_interface']} proto {policy['protocol']} from {policy['source']} to {policy['destination']}")
    return {
        'policy_id': policy.get('id'),
        'policy_type': policy_type,
        'firewall_rule': firewall_rule,
        'nat': nat,
        'risks': risks,
        'equivalent_configuration': equivalent,
        'safe_mode_note': 'Preview solamente: no aplica cambios reales ni ejecuta shell.',
    }


def apply_policy(policy_id: str, *, organization=None, safe_mode=True) -> dict[str, Any]:
    policy = get_policy(policy_id, organization=organization)
    preview = preview_policy(policy)
    if safe_mode:
        return {
            'ok': False,
            'applied': False,
            'message': 'safe_mode activo, aplicación real bloqueada',
            'policy': policy,
            'preview': preview,
            'apply_backend': 'future_opnsense_api',
        }
    return {
        'ok': False,
        'applied': False,
        'message': 'Aplicación real aún no implementada; usar OPNsense API con rollback antes de habilitar.',
        'policy': policy,
        'preview': preview,
        'apply_backend': 'future_opnsense_api',
    }


def handle_command(command_type: str, payload: dict[str, Any] | None = None, *, organization=None, safe_mode=True) -> dict[str, Any]:
    payload = payload or {}
    try:
        if command_type == 'firewall.policies.list':
            return {'ok': True, 'policies': list_policies(organization)}
        if command_type == 'firewall.policy.create':
            return create_policy(payload, organization=organization, safe_mode=safe_mode)
        if command_type == 'firewall.policy.disable':
            return disable_policy(str(payload.get('id') or payload.get('policy_id') or ''), organization=organization)
        if command_type == 'firewall.policy.preview':
            if payload.get('policy'):
                policy = validate_policy(payload['policy'])
            else:
                policy = get_policy(str(payload.get('id') or payload.get('policy_id') or ''), organization=organization)
            return {'ok': True, 'preview': preview_policy(policy), 'policy': policy}
        if command_type == 'firewall.policy.apply':
            return apply_policy(str(payload.get('id') or payload.get('policy_id') or ''), organization=organization, safe_mode=safe_mode)
        raise PolicyValidationError('Tipo de comando no soportado.')
    except (PolicyValidationError, ValidationError) as exc:
        return {'ok': False, 'error': str(exc)}
