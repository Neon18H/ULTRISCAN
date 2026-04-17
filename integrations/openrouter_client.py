from __future__ import annotations

import json
import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)


class OpenRouterClient:
    def __init__(self, *, api_key: str, base_url: str, model: str, timeout: int = 45):
        self.api_key = (api_key or '').strip()
        self.base_url = (base_url or 'https://openrouter.ai/api/v1').rstrip('/')
        self.model = (model or '').strip()
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and self.model)

    def create_structured_completion(
        self,
        *,
        system_prompt: str,
        user_payload: dict[str, Any],
        schema_name: str,
        json_schema: dict[str, Any],
    ) -> dict[str, Any]:
        if not self.enabled:
            raise ValueError('OpenRouter is not configured (missing API key or model).')

        payload = {
            'model': self.model,
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': json.dumps(user_payload, ensure_ascii=False)},
            ],
            'temperature': 0.1,
            'response_format': {
                'type': 'json_schema',
                'json_schema': {
                    'name': schema_name,
                    'strict': True,
                    'schema': json_schema,
                },
            },
        }

        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
        }
        url = f'{self.base_url}/chat/completions'
        response = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        response.raise_for_status()
        body = response.json()

        message = (((body.get('choices') or [{}])[0]).get('message') or {})
        content = message.get('content')
        if isinstance(content, list):
            text = ''.join(item.get('text', '') for item in content if isinstance(item, dict))
        else:
            text = content or ''
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            logger.warning('OpenRouter returned non-JSON content for model=%s', self.model)
            raise
