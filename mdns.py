"""mDNS discovery helpers for Scream Router."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import TYPE_CHECKING, NotRequired, TypedDict

from zeroconf import ServiceInfo, ServiceStateChange
from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf

from .const import LOGGER

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
else:
    HomeAssistant = "HomeAssistant"

MDNS_SERVICE_TYPES: tuple[str, ...] = (
    "_screamrouter._tcp.local.",
    "_screamrouter._tcp.",
)
MDNS_SCAN_SECONDS = 3
MDNS_REFRESH_INTERVAL = timedelta(seconds=30)

_ZEROCONF: AsyncZeroconf | None = None
_ZEROCONF_LOCK = asyncio.Lock()


class DiscoveredServer(TypedDict, total=False):
    """Information about a discovered server."""

    name: str
    uuid: NotRequired[str]


def normalize_uuid(raw_uuid: str | bytes | None) -> str | None:
    """Normalize UUID values from mDNS TXT records."""
    if not raw_uuid:
        return None
    if isinstance(raw_uuid, bytes):
        uuid_str = raw_uuid.decode("utf-8", "ignore")
    else:
        uuid_str = raw_uuid
    cleaned = uuid_str.strip()
    if not cleaned:
        return None
    return cleaned.lower()


def _select_host(addresses: list[str]) -> str | None:
    if not addresses:
        return None
    for addr in addresses:
        if not addr.startswith("127."):
            return addr
    return addresses[0]


def _extract_uuid(info: ServiceInfo) -> str | None:
    properties = getattr(info, "properties", None) or {}
    for key, value in properties.items():
        key_str = key.decode("utf-8", "ignore")
        if key_str.lower() != "uuid":
            continue
        return normalize_uuid(value)
    return None


async def _async_get_zeroconf(hass: HomeAssistant) -> AsyncZeroconf:
    """Return the shared Home Assistant AsyncZeroconf instance."""
    global _ZEROCONF  # noqa: PLW0603
    if _ZEROCONF is not None:
        return _ZEROCONF
    async with _ZEROCONF_LOCK:
        if _ZEROCONF is None:
            from homeassistant.components.zeroconf import async_get_instance

            _ZEROCONF = AsyncZeroconf()
        return _ZEROCONF


async def async_discover_mdns(hass: HomeAssistant | None = None) -> dict[str, DiscoveredServer]:
    """Discover available ScreamRouter servers over mDNS."""
    global _ZEROCONF
    discovered: dict[str, DiscoveredServer] = {}
    uuid_to_url: dict[str, str] = {}
    aiozc: AsyncZeroconf | None = None
    browsers: list[AsyncServiceBrowser] = []
    owns_zeroconf = False

    aiozc = AsyncZeroconf()

    tasks: set[asyncio.Task] = set()
    loop = asyncio.get_running_loop()

    async def _async_process_service(service_type: str, name: str) -> None:
        assert aiozc
        info = await aiozc.async_get_service_info(service_type, name)
        if info is None:
            return
        host = _select_host(info.parsed_addresses())
        if not host:
            return
        port = info.port or 80
        service_name = info.name.rstrip(".")
        url = f"https://{host}:{port}"
        uuid = _extract_uuid(info)

        entry: DiscoveredServer = {"name": service_name}
        if uuid:
            entry["uuid"] = uuid
            existing_url = uuid_to_url.get(uuid)
            if existing_url and existing_url != url:
                discovered.pop(existing_url, None)
            uuid_to_url[uuid] = url

        discovered[url] = entry

    def _on_service_state_change(
        zeroconf, service_type: str, name: str, state_change: ServiceStateChange
    ) -> None:
        if state_change is not ServiceStateChange.Added:
            return
        task = loop.create_task(_async_process_service(service_type, name))
        task.add_done_callback(tasks.discard)
        tasks.add(task)

    try:
        zeroconf_instance = aiozc.zeroconf
        browsers = [
            AsyncServiceBrowser(
                zeroconf_instance,
                service_type,
                handlers=[_on_service_state_change],
            )
            for service_type in MDNS_SERVICE_TYPES
        ]
        await asyncio.sleep(MDNS_SCAN_SECONDS)
    except Exception:  # pylint: disable=broad-except
        LOGGER.debug("mDNS discovery for ScreamRouter failed", exc_info=True)
    finally:
        for browser in browsers:
            await browser.async_cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if owns_zeroconf and aiozc is not None:
            await aiozc.async_close()

    LOGGER.debug("Discovered ScreamRouter servers via mDNS: %s", discovered)
    return discovered
