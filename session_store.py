"""Persistent storage for ScreamRouter sessions keyed by UUID."""

from __future__ import annotations

import asyncio
from collections.abc import MutableMapping
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import LOGGER

STORAGE_VERSION = 1
STORAGE_KEY = "scream_router.sessions"

SessionRecord = dict[str, Any]


class SessionStore:
    """Async wrapper around Home Assistant Store for UUID-to-session mapping."""

    def __init__(self, hass: HomeAssistant) -> None:
        LOGGER.debug("SessionStore: initializing for hass=%s", hass)
        self._store = Store(hass, STORAGE_VERSION, STORAGE_KEY)
        self._cache: MutableMapping[str, SessionRecord] | None = None
        self._lock = asyncio.Lock()

    async def async_load(self) -> None:
        """Ensure the cache is populated from disk."""
        LOGGER.debug("SessionStore.async_load: cache_initialized=%s", self._cache is not None)
        if self._cache is not None:
            return
        async with self._lock:
            if self._cache is None:
                stored = await self._store.async_load()
                self._cache = stored or {}
                LOGGER.debug(
                    "SessionStore.async_load: loaded %d entries from storage",
                    len(self._cache),
                )

    def _ensure_cache(self) -> MutableMapping[str, SessionRecord]:
        if self._cache is None:
            raise RuntimeError("SessionStore cache not loaded; call async_load() first")
        return self._cache

    async def async_get(self, uuid: str) -> SessionRecord | None:
        """Return stored record for uuid, if any."""
        LOGGER.debug("SessionStore.async_get: uuid=%s", uuid)
        await self.async_load()
        return self._ensure_cache().get(uuid)

    async def async_set(self, uuid: str, url: str) -> None:
        """Persist or update a UUID mapping."""
        LOGGER.debug("SessionStore.async_set: uuid=%s url=%s", uuid, url)
        await self.async_load()
        cache = self._ensure_cache()
        cache[uuid] = {"url": url}
        await self._store.async_save(cache)
        LOGGER.debug("SessionStore.async_set: stored uuid=%s (total=%d)", uuid, len(cache))

    async def async_remove(self, uuid: str) -> None:
        """Remove a UUID mapping if it exists."""
        LOGGER.debug("SessionStore.async_remove: uuid=%s", uuid)
        await self.async_load()
        cache = self._ensure_cache()
        if uuid in cache:
            cache.pop(uuid)
            await self._store.async_save(cache)
            LOGGER.debug(
                "SessionStore.async_remove: removed uuid=%s (remaining=%d)",
                uuid,
                len(cache),
            )
        else:
            LOGGER.debug("SessionStore.async_remove: uuid=%s not present", uuid)
