"""Class to access the ScreamRouter API."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import aiohttp
from aiohttp import ClientError

from .const import (
    LOGGER,
    REQUEST_RETRY_ATTEMPTS,
    REQUEST_RETRY_BACKOFF_SECONDS,
    REQUEST_TIMEOUT_SECONDS,
)


class ScreamRouter:
    """Talks to a ScreamRouter."""

    def __init__(self, url: str) -> None:
        """Initialize the config."""
        self.url: str = url
        """URL to connect to."""
        self._max_attempts: int = REQUEST_RETRY_ATTEMPTS
        self._backoff_seconds: int = REQUEST_RETRY_BACKOFF_SECONDS

    def set_base_url(self, url: str) -> None:
        """Update the base URL used for subsequent API calls."""
        self.url = url

    async def __call_api(
        self,
        endpoint: str,
        method: str,
        body_json: dict[str, Any] | None = None,
    ) -> dict | list[Any]:
        """ScreamRouter API object."""
        url: str = f"{self.url}{endpoint}"
        last_exception: Exception | None = None

        for attempt in range(1, self._max_attempts + 1):
            try:
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(verify_ssl=False),
                    timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS),
                ) as http:
                    async with http.request(method, url, json=body_json) as resp:
                        resp.raise_for_status()
                        if resp.content_length == 0:
                            return {}
                        content_type = resp.headers.get("Content-Type", "").lower()
                        if content_type.startswith("application/json"):
                            return await resp.json(content_type=None)
                        return json.loads(await resp.text())
            except (ClientError, asyncio.TimeoutError, json.JSONDecodeError) as exc:
                last_exception = exc
                LOGGER.warning(
                    "Attempt %s/%s calling %s failed: %s",
                    attempt,
                    self._max_attempts,
                    url,
                    exc,
                )
                if attempt == self._max_attempts:
                    break
                await asyncio.sleep(self._backoff_seconds * attempt)

        assert last_exception is not None
        raise last_exception

    async def get_sinks(self) -> dict | list[Any]:
        """Get a parsed block of JSON representing the sinks."""
        return await self.__call_api("/sinks", "GET")

    async def get_sources(self) -> dict | list[Any]:
        """Get a parsed block of JSON representing the sources."""
        return await self.__call_api("/sources", "GET")

    async def get_routes(self) -> dict | list[Any]:
        """Get a parsed block of JSON representing the routes."""
        return await self.__call_api("/routes", "GET")

    async def change_sink_volume(self, sink_name: str, volume: float) -> None:
        """Change a sink indicated by sink_name to the specified volume."""
        await self.__call_api(f"/sinks/{sink_name}/volume/{volume}/", "GET")

    async def disable_sink(self, sink_name: str) -> None:
        """Disable a sink indicated by sink_name."""
        await self.__call_api(f"/sinks/{sink_name}/disable/", "GET")

    async def enable_sink(self, sink_name: str) -> None:
        """Enable a sink indicated by sink_name."""
        await self.__call_api(f"/sinks/{sink_name}/enable/", "GET")

    async def change_source_volume(self, source_name: str, volume: float) -> None:
        """Change a source indicated by source_name to the specified volume."""
        await self.__call_api(f"/sources/{source_name}/volume/{volume}/", "GET")

    async def disable_source(self, source_name: str) -> None:
        """Disable a source indicated by source_name."""
        await self.__call_api(f"/sources/{source_name}/disable/", "GET")

    async def enable_source(self, source_name: str) -> None:
        """Enable a source indicated by source_name."""
        await self.__call_api(f"/sources/{source_name}/enable/", "GET")

    async def change_route_volume(self, route_name: str, volume: float) -> None:
        """Change a route indicated by route_name to the specified volume."""
        await self.__call_api(f"/routes/{route_name}/volume/{volume}/", "GET")

    async def disable_route(self, route_name: str) -> None:
        """Disable a route indicated by route_name."""
        await self.__call_api(f"/routes/{route_name}/disable/", "GET")

    async def enable_route(self, route_name: str) -> None:
        """Enable a route indicated by route_name."""
        await self.__call_api(f"/routes/{route_name}/enable/", "GET")

    async def play_url(self, sink_name: str, url: str, volume: float = 1) -> None:
        """Play a URL on a sink indicated by sink_name."""
        url = url.replace("172.17.0.3", "192.168.3.153")
        await self.__call_api(f"/sinks/{sink_name}/play/{volume}", "POST", {"url": url})
