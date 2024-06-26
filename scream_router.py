"""Class to access the ScreamRouter API."""

import json

import aiohttp
from .const import LOGGER


class ScreamRouter:
    """Talks to a ScreamRouter."""

    def __init__(self, url: str) -> None:
        """Initialize the config."""
        self.url: str = url
        """URL to connect to."""

    async def __call_api(
        self, endpoint: str, method: str, body_json: dict | None = None
    ) -> dict:
        """ScreamRouter API object."""
        url: str = f"{self.url}{endpoint}"
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=False)) as http:
            if method == "GET":
                async with http.get(url) as resp:
                    return json.loads(await resp.text())
            if method == "POST":
                async with http.post(url, json=body_json) as resp:
                    return json.loads(await resp.text())
            if method == "PUT":
                async with http.put(url, json=body_json) as resp:
                    return json.loads(await resp.text())
        return {}

    async def get_sinks(self) -> dict:
        """Get a parsed block of JSON representing the sinks."""
        return await self.__call_api("/sinks", "GET")

    async def get_sources(self) -> dict:
        """Get a parsed block of JSON representing the sources."""
        return await self.__call_api("/sources", "GET")

    async def get_routes(self) -> dict:
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
