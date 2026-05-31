PROVIDER_CATALOG = {
    'aws': {
        'key': 'aws',
        'name': 'AWS',
        'logo': 'bi-cloud-fill',
        'color': '#ff9900',
        'description': 'Amazon Web Services resources such as EC2 instances and VPC workloads.',
    },
    'azure': {
        'key': 'azure',
        'name': 'Microsoft Azure',
        'logo': 'bi-microsoft',
        'color': '#0078d4',
        'description': 'Microsoft Azure virtual machines and private cloud resources.',
    },
    'gcp': {
        'key': 'gcp',
        'name': 'Google Cloud',
        'logo': 'bi-google',
        'color': '#4285f4',
        'description': 'Google Cloud workloads such as Compute Engine instances.',
    },
    'contabo': {
        'key': 'contabo',
        'name': 'Contabo',
        'logo': 'bi-server',
        'color': '#00a6eb',
        'description': 'Contabo VPS, VDS and dedicated server resources.',
    },
    'hetzner': {
        'key': 'hetzner',
        'name': 'Hetzner',
        'logo': 'bi-hdd-rack',
        'color': '#d50c2d',
        'description': 'Hetzner cloud servers and private network resources.',
    },
    'onprem': {
        'key': 'onprem',
        'name': 'On-Prem',
        'logo': 'bi-building',
        'color': '#475569',
        'description': 'On-premises systems behind the firewall gateway.',
    },
    'other': {
        'key': 'other',
        'name': 'Otro',
        'logo': 'bi-box',
        'color': '#64748b',
        'description': 'External or custom provider not covered by the catalog.',
    },
}


def provider_choices():
    return [(key, provider['name']) for key, provider in PROVIDER_CATALOG.items()]


def get_provider(key):
    return PROVIDER_CATALOG.get(key or 'other', PROVIDER_CATALOG['other'])
