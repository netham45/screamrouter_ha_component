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
    SESSION_STORE,
    SINKS,
    SOURCES,
)
from .mdns import MDNS_REFRESH_INTERVAL, async_discover_mdns, normalize_uuid
from .scream_router import ScreamRouter
from .session_store import SessionStore

PLATFORMS = [Platform.MEDIA_PLAYER]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Scream Router from a config entry."""
    LOGGER.debug(
        "async_setup_entry: entry_id=%s data=%s",
        entry.entry_id,
        entry.data,
    )
    config = entry.data
    domain_data = hass.data.setdefault(DOMAIN, {})
    session_store: SessionStore = domain_data.setdefault(
        SESSION_STORE, SessionStore(hass)
    )
    await session_store.async_load()
    LOGGER.debug("async_setup_entry: session store loaded")

    entry_uuid = config.get(CONF_UUID)
    normalized_uuid = normalize_uuid(entry_uuid) if entry_uuid else None
    LOGGER.debug(
        "async_setup_entry: entry_uuid=%s normalized_uuid=%s",
        entry_uuid,
        normalized_uuid,
    )
    stored_record = (
        await session_store.async_get(normalized_uuid) if normalized_uuid else None
    )
    stored_url = stored_record["url"] if stored_record else None
    entry_url = config.get(CONF_URL)
    LOGGER.debug(
        "async_setup_entry: stored_url=%s entry_url=%s",
        stored_url,
        entry_url,
    )

    candidate_urls: list[str] = []
    if stored_url:
        LOGGER.debug("async_setup_entry: prioritizing stored URL %s", stored_url)
        candidate_urls.append(stored_url)
    if entry_url and entry_url not in candidate_urls:
        LOGGER.debug("async_setup_entry: adding config entry URL %s", entry_url)
        candidate_urls.append(entry_url)

    if not candidate_urls:
        LOGGER.debug(
            "async_setup_entry: no candidate URLs resolved; raising ConfigEntryNotReady"
        )
        raise ConfigEntryNotReady(
            "No stored URL available for Scream Router session; waiting for discovery"
        )

    base_url: str | None = None
    scream_router: ScreamRouter | None = None
    sinks: dict[str, Any] | list[Any] | None = None
    sources: dict[str, Any] | list[Any] | None = None
    routes: dict[str, Any] | list[Any] | None = None
    last_exception: Exception | None = None

    for idx, candidate_url in enumerate(candidate_urls):
        LOGGER.debug(
            "async_setup_entry: attempting candidate_url=%s (index=%d)",
            candidate_url,
            idx,
        )
        scream_router = ScreamRouter(candidate_url)
        try:
            sinks = await scream_router.get_sinks()
            sources = await scream_router.get_sources()
            routes = await scream_router.get_routes()
        except Exception as exc:  # pylint: disable=broad-except
            last_exception = exc
            if idx == len(candidate_urls) - 1:
                LOGGER.warning(
                    "Failed to query Scream Router during setup: %s", exc
                )
            else:
                LOGGER.debug(
                    "Stored URL %s failed during setup, retrying with fallback",
                    candidate_url,
                    exc_info=True,
                )
            continue
        base_url = candidate_url
        LOGGER.debug("async_setup_entry: connected successfully to %s", base_url)
        break

    if base_url is None or scream_router is None or sinks is None or sources is None or routes is None:
        assert last_exception is not None
        LOGGER.debug(
            "async_setup_entry: all candidate URLs failed; re-raising last exception"
        )
        raise ConfigEntryNotReady from last_exception

    if stored_url and stored_url != base_url:
        LOGGER.info(
            "Falling back to config entry URL %s after stored URL %s failed",
            base_url,
            stored_url,
        )

    if normalized_uuid:
        data_without_url = {
            key: value for key, value in entry.data.items() if key != CONF_URL
        }
        if data_without_url != entry.data:
            LOGGER.debug(
                "async_setup_entry: removing CONF_URL from config entry (uuid-driven)"
            )
            hass.config_entries.async_update_entry(entry, data=data_without_url)
    elif entry_url != base_url:
        LOGGER.debug(
            "async_setup_entry: updating CONF_URL from %s to %s",
            entry_url,
            base_url,
        )
        hass.config_entries.async_update_entry(
            entry,
            data={**entry.data, CONF_URL: base_url},
        )

    available = True

    entry_data = domain_data[entry.entry_id] = {
        SINKS: sinks,
        SOURCES: sources,
        ROUTES: routes,
        DATA_AVAILABLE: available,
        SCREAM_ROUTER_SERVER: scream_router,
        SESSION_STORE: session_store,
    }
    LOGGER.debug(
        "async_setup_entry: stored runtime data keys=%s",
        list(entry_data.keys()),
    )

    if normalized_uuid and (
        stored_record is None or stored_record.get("url") != base_url
    ):
        LOGGER.debug(
            "async_setup_entry: persisting url=%s for uuid=%s",
            base_url,
            normalized_uuid,
        )
        await session_store.async_set(normalized_uuid, base_url)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    LOGGER.debug("async_setup_entry: platform setup forwarding complete")

    if normalized_uuid:
        LOGGER.debug(
            "async_setup_entry: scheduling immediate mDNS refresh and watch task"
        )
        hass.async_create_task(_async_refresh_mdns(hass, entry))
        entry_data[MDNS_REFRESH_TASK] = hass.loop.create_task(
            _async_mdns_watch(hass, entry.entry_id)
        )

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    LOGGER.debug("async_unload_entry: entry_id=%s", entry.entry_id)
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if not unload_ok:
        LOGGER.debug("async_unload_entry: platform unload failed for %s", entry.entry_id)
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
            LOGGER.debug(
                "async_unload_entry: cancelled mDNS task for entry_id=%s",
                entry.entry_id,
            )

    entry_uuid = entry.data.get(CONF_UUID)
    if entry_uuid and domain_data is not None:
        session_store: SessionStore | None = domain_data.get(SESSION_STORE)
        normalized_uuid = normalize_uuid(entry_uuid)
        if session_store and normalized_uuid:
            LOGGER.debug(
                "async_unload_entry: removing uuid=%s from session store",
                normalized_uuid,
            )
            await session_store.async_remove(normalized_uuid)

    return True


async def _async_mdns_watch(hass: HomeAssistant, entry_id: str) -> None:
    """Continuously refresh mDNS data for an entry."""
    interval = MDNS_REFRESH_INTERVAL.total_seconds()
    LOGGER.debug("_async_mdns_watch: entry_id=%s interval=%s", entry_id, interval)
    try:
        while True:
            entry = hass.config_entries.async_get_entry(entry_id)
            if entry and entry.state is ConfigEntryState.LOADED:
                LOGGER.debug("_async_mdns_watch: triggering refresh for entry_id=%s", entry_id)
                await _async_refresh_mdns(hass, entry)
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        LOGGER.debug("_async_mdns_watch: cancelled for entry_id=%s", entry_id)
        return


async def _async_refresh_mdns(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Refresh mDNS data and update the entry URL if the UUID has moved."""
    uuid = entry.data.get(CONF_UUID)
    if not uuid:
        LOGGER.debug(
            "_async_refresh_mdns: entry %s has no UUID; skipping",
            entry.entry_id,
        )
        return

    normalized_entry_uuid = normalize_uuid(uuid)
    if not normalized_entry_uuid:
        LOGGER.debug(
            "_async_refresh_mdns: unable to normalize UUID %s for entry %s",
            uuid,
            entry.entry_id,
        )
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
    LOGGER.debug(
        "_async_refresh_mdns: entry_id=%s target_url=%s",
        entry.entry_id,
        target_url,
    )

    domain_data = hass.data.setdefault(DOMAIN, {})
    entry_domain_data = domain_data.get(entry.entry_id)
    if not entry_domain_data:
        LOGGER.debug(
            "_async_refresh_mdns: no domain data for entry %s; skipping",
            entry.entry_id,
        )
        return
    scream_router: ScreamRouter | None = entry_domain_data.get(SCREAM_ROUTER_SERVER)
    if scream_router is None:
        LOGGER.debug(
            "_async_refresh_mdns: ScreamRouter client missing for entry %s",
            entry.entry_id,
        )
        return
    session_store: SessionStore | None = entry_domain_data.get(SESSION_STORE)

    stored_record = (
        await session_store.async_get(normalized_entry_uuid)
        if session_store
        else None
    )

    current_url = entry.data.get(CONF_URL) or (
        stored_record.get("url") if stored_record else None
    )
    LOGGER.debug(
        "_async_refresh_mdns: current_url=%s stored_record=%s",
        current_url,
        stored_record,
    )

    if not target_url or current_url == target_url:
        LOGGER.debug(
            "_async_refresh_mdns: no update required (target=%s current=%s)",
            target_url,
            current_url,
        )
        return

    LOGGER.info(
        "Updating Scream Router %s URL from %s to %s based on mDNS discovery",
        entry.title or entry.entry_id,
        current_url,
        target_url,
    )

    scream_router.set_base_url(target_url)

    if session_store:
        LOGGER.debug(
            "_async_refresh_mdns: updating session store uuid=%s url=%s",
            normalized_entry_uuid,
            target_url,
        )
        await session_store.async_set(normalized_entry_uuid, target_url)

    if entry.data.get(CONF_UUID):
        if entry.data.get(CONF_URL):
            LOGGER.debug(
                "_async_refresh_mdns: removing CONF_URL from entry data"
            )
            hass.config_entries.async_update_entry(
                entry,
                data={
                    key: value
                    for key, value in entry.data.items()
                    if key != CONF_URL
                },
            )
    else:
        LOGGER.debug(
            "_async_refresh_mdns: updating entry CONF_URL to %s",
            target_url,
        )
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
    LOGGER.debug(
        "_async_refresh_mdns: refreshed data after URL update (sinks=%s sources=%s routes=%s)",
        len(sinks) if isinstance(sinks, list) else (len(sinks) if sinks else 0),
        len(sources) if isinstance(sources, list) else (len(sources) if sources else 0),
        len(routes) if isinstance(routes, list) else (len(routes) if routes else 0),
    )

    entry_domain_data[SINKS] = sinks
    entry_domain_data[SOURCES] = sources
    entry_domain_data[ROUTES] = routes
