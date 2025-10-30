"""The Scream Router integration."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from typing import Any

from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.const import CONF_URL, CONF_UUID, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .const import (
    DATA_AVAILABLE,
    DOMAIN,
    LOGGER,
    MDNS_REFRESH_TASK,
    ROUTES,
    SCREAM_ROUTER_SERVER,
    SINKS,
    SOURCES,
)
from .mdns import MDNS_REFRESH_INTERVAL, async_discover_mdns, normalize_uuid
from .scream_router import ScreamRouter

PLATFORMS = [Platform.MEDIA_PLAYER]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Scream Router from a config entry."""
    config = entry.data

    url = config[CONF_URL]
    scream_router: ScreamRouter = ScreamRouter(url)
    available = True
    try:
        sinks: dict[str, Any] | list[Any] = await scream_router.get_sinks()
        sources: dict[str, Any] | list[Any] = await scream_router.get_sources()
        routes: dict[str, Any] | list[Any] = await scream_router.get_routes()
    except Exception as exc:
        LOGGER.warning("Failed to query Scream Router during setup: %s", exc)
        raise ConfigEntryNotReady from exc

    domain_data = hass.data.setdefault(DOMAIN, {})
    entry_data = domain_data[entry.entry_id] = {
        SINKS: sinks,
        SOURCES: sources,
        ROUTES: routes,
        DATA_AVAILABLE: available,
        SCREAM_ROUTER_SERVER: scream_router,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    if entry.data.get(CONF_UUID):
        hass.async_create_task(_async_refresh_mdns(hass, entry))
        entry_data[MDNS_REFRESH_TASK] = hass.loop.create_task(
            _async_mdns_watch(hass, entry.entry_id)
        )

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if not unload_ok:
        return False

    domain_data = hass.data.get(DOMAIN)
    if domain_data is None:
        return True

    entry_data = domain_data.pop(entry.entry_id, None)
    if isinstance(entry_data, dict):
        task = entry_data.pop(MDNS_REFRESH_TASK, None)
        if task:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    return True


async def _async_mdns_watch(hass: HomeAssistant, entry_id: str) -> None:
    """Continuously refresh mDNS data for an entry."""
    interval = MDNS_REFRESH_INTERVAL.total_seconds()
    try:
        while True:
            entry = hass.config_entries.async_get_entry(entry_id)
            if entry and entry.state is ConfigEntryState.LOADED:
                await _async_refresh_mdns(hass, entry)
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        return


async def _async_refresh_mdns(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Refresh mDNS data and update the entry URL if the UUID has moved."""
    uuid = entry.data.get(CONF_UUID)
    if not uuid:
        return

    normalized_entry_uuid = normalize_uuid(uuid)
    if not normalized_entry_uuid:
        return

    try:
        discoveries = await async_discover_mdns(hass)
    except Exception:  # pylint: disable=broad-except
        LOGGER.debug("mDNS refresh failed", exc_info=True)
        return

    target_url: str | None = None
    for url, details in discoveries.items():
        if normalize_uuid(details.get("uuid")) == normalized_entry_uuid:
            target_url = url
            break

    if not target_url:
        return

    current_url = entry.data.get(CONF_URL)
    if current_url == target_url:
        return

    LOGGER.info(
        "Updating Scream Router %s URL from %s to %s based on mDNS discovery",
        entry.title or entry.entry_id,
        current_url,
        target_url,
    )

    domain_data = hass.data.setdefault(DOMAIN, {})
    entry_domain_data = domain_data.get(entry.entry_id)
    if not entry_domain_data:
        return
    scream_router: ScreamRouter | None = entry_domain_data.get(SCREAM_ROUTER_SERVER)
    if scream_router is None:
        return

    scream_router.set_base_url(target_url)

    hass.config_entries.async_update_entry(
        entry,
        data={**entry.data, CONF_URL: target_url},
    )

    try:
        sinks: dict[str, Any] | list[Any] = await scream_router.get_sinks()
        sources: dict[str, Any] | list[Any] = await scream_router.get_sources()
        routes: dict[str, Any] | list[Any] = await scream_router.get_routes()
    except Exception:  # pylint: disable=broad-except
        LOGGER.debug("Failed to refresh ScreamRouter data after URL update", exc_info=True)
        return

    entry_domain_data[SINKS] = sinks
    entry_domain_data[SOURCES] = sources
    entry_domain_data[ROUTES] = routes
