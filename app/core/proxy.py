"""
OmniBioAI app.core.proxy.

Purpose:
    Defines ProxyClient with forward methods for app.core.proxy.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

import httpx
from app.core.config import Config


class ProxyClient:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=Config.ROUTE_TIMEOUT)

    async def forward(self, url: str, method: str, headers=None, body=None):
        try:
            response = await self.client.request(
                method=method,
                url=url,
                headers=headers,
                json=body,
            )

            return response.status_code, response.json()

        except Exception as e:
            return 500, {"error": "upstream_failure", "detail": str(e)}