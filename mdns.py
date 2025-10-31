"""mDNS discovery helpers for Scream Router."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import TYPE_CHECKING, NotRequired, TypedDict

from zeroconf import ServiceInfo, ServiceStateChange
from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf

from .const import LOGGER

import homeassistant.components.zeroconf

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
else:
    HomeAssistant = "HomeAssistant"

MDNS_SERVICE_TYPES: tuple[str, ...] = (
    "_screamrouter._tcp.local.",
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
    LOGGER.debug("normalize_uuid: raw_uuid=%s (type=%s)", raw_uuid, type(raw_uuid).__name__)
    if not raw_uuid:
        LOGGER.debug("normalize_uuid: received empty value, returning None")
        return None
    if isinstance(raw_uuid, bytes):
        uuid_str = raw_uuid.decode("utf-8", "ignore")
    else:
        uuid_str = raw_uuid
    cleaned = uuid_str.strip()
    if not cleaned:
        LOGGER.debug("normalize_uuid: string empty after strip, returning None")
        return None
    normalized = cleaned.lower()
    LOGGER.debug("normalize_uuid: normalized=%s", normalized)
    return normalized


def _select_host(addresses: list[str]) -> str | None:
    LOGGER.debug("_select_host: candidate addresses=%s", addresses)
    if not addresses:
        LOGGER.debug("_select_host: no addresses available")
        return None
    for addr in addresses:
        if not addr.startswith("127."):
            LOGGER.debug("_select_host: selected non-loopback address=%s", addr)
            return addr
    LOGGER.debug("_select_host: only loopback addresses, returning first=%s", addresses[0])
    return addresses[0]


def _extract_uuid(info: ServiceInfo) -> str | None:
    LOGGER.debug("_extract_uuid: evaluating ServiceInfo name=%s properties=%s", info.name, getattr(info, "properties", {}))
    properties = getattr(info, "properties", None) or {}
    for key, value in properties.items():
        key_str = key.decode("utf-8", "ignore")
        if key_str.lower() != "uuid":
            continue
        normalized = normalize_uuid(value)
        LOGGER.debug("_extract_uuid: found uuid property=%s normalized=%s", value, normalized)
        return normalized
    LOGGER.debug("_extract_uuid: no uuid property found")
    return None


async def _async_get_zeroconf(hass: HomeAssistant) -> AsyncZeroconf:
    """Return the shared Home Assistant AsyncZeroconf instance."""
    global _ZEROCONF  # noqa: PLW0603
    if _ZEROCONF is not None:
        LOGGER.debug("_async_get_zeroconf: reusing existing AsyncZeroconf instance")
        return _ZEROCONF
    async with _ZEROCONF_LOCK:
        if _ZEROCONF is None:
            from homeassistant.components.zeroconf import async_get_instance
            LOGGER.debug("_async_get_zeroconf: creating new AsyncZeroconf")
            _ZEROCONF = AsyncZeroconf()
        return _ZEROCONF


async def async_discover_mdns(hass: HomeAssistant | None = None) -> dict[str, DiscoveredServer]:
    """Discover available ScreamRouter servers over mDNS."""
    global _ZEROCONF
    LOGGER.debug("async_discover_mdns: starting discovery hass_provided=%s", hass is not None)
    discovered: dict[str, DiscoveredServer] = {}
    uuid_to_url: dict[str, str] = {}
    aiozc: AsyncZeroconf | None = None
    browsers: list[AsyncServiceBrowser] = []
    owns_zeroconf = False

    if hass:
        LOGGER.debug("async_discover_mdns: obtaining shared AsyncZeroconf from Home Assistant")
        aiozc = await homeassistant.components.zeroconf.async_get_instance(hass)
    else:
        LOGGER.debug("async_discover_mdns: creating stand-alone AsyncZeroconf")
        aiozc = AsyncZeroconf()
        owns_zeroconf = True

    tasks: set[asyncio.Task] = set()
    loop = asyncio.get_running_loop()

    async def _async_process_service(service_type: str, name: str) -> None:
        assert aiozc
        LOGGER.debug("_async_process_service: requesting info for service_type=%s name=%s", service_type, name)
        info = await aiozc.async_get_service_info(service_type, name)
        if info is None:
            LOGGER.debug("_async_process_service: no ServiceInfo returned for %s (%s)", name, service_type)
            return
        host = _select_host(info.parsed_addresses())
        if not host:
            LOGGER.debug("_async_process_service: no suitable host in addresses=%s", info.parsed_addresses())
            return
        port = info.port
        service_name = info.name.rstrip(".")
        url = f"https://{host}:{port}"
        uuid = _extract_uuid(info)

        entry: DiscoveredServer = {"name": service_name}
        if uuid:
            entry["uuid"] = uuid
            existing_url = uuid_to_url.get(uuid)
            if existing_url and existing_url != url:
                LOGGER.debug(
                    "_async_process_service: UUID %s already mapped to %s, replacing with %s",
                    uuid,
                    existing_url,
                    url,
                )
                discovered.pop(existing_url, None)
            uuid_to_url[uuid] = url
        else:
            LOGGER.debug("_async_process_service: service %s did not expose a UUID", service_name)

        LOGGER.debug(
            "_async_process_service: storing discovery url=%s entry=%s", url, entry
        )
        discovered[url] = entry

    def _on_service_state_change(
        zeroconf, service_type: str, name: str, state_change: ServiceStateChange
    ) -> None:
        LOGGER.debug(
            "_on_service_state_change: service_type=%s name=%s state=%s",
            service_type,
            name,
            state_change,
        )
        if state_change is not ServiceStateChange.Added:
            LOGGER.debug("_on_service_state_change: ignoring state change %s", state_change)
            return
        task = loop.create_task(_async_process_service(service_type, name))
        task.add_done_callback(tasks.discard)
        tasks.add(task)

    try:
        LOGGER.debug(
            "async_discover_mdns: creating AsyncServiceBrowsers for types=%s", MDNS_SERVICE_TYPES
        )
        zeroconf_instance = aiozc.zeroconf if aiozc.zeroconf else aiozc
        browsers = [
            AsyncServiceBrowser(
                zeroconf_instance,
                service_type,
                handlers=[_on_service_state_change],
            )
            for service_type in MDNS_SERVICE_TYPES
        ]
        LOGGER.debug("async_discover_mdns: sleeping for %s seconds to collect services", MDNS_SCAN_SECONDS)
        await asyncio.sleep(MDNS_SCAN_SECONDS)
    except Exception:  # pylint: disable=broad-except
        LOGGER.debug("mDNS discovery for ScreamRouter failed", exc_info=True)
    finally:
        for browser in browsers:
            await browser.async_cancel()
        LOGGER.debug(
            "async_discover_mdns: awaiting %d outstanding service tasks", len(tasks)
        )
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if owns_zeroconf and aiozc is not None:
            LOGGER.debug("async_discover_mdns: closing stand-alone AsyncZeroconf")
            await aiozc.async_close()

    LOGGER.debug("Discovered ScreamRouter servers via mDNS: %s", discovered)
    return discovered
