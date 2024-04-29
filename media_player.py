"""Provide functionality to interact with the ScreamRouter interface."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Coroutine
from functools import wraps
import hashlib
from typing import Any, Concatenate, List, ParamSpec, TypeVar

from homeassistant.components import media_source
from homeassistant.components.media_player import (
    BrowseMedia,
    MediaPlayerEntity,
    MediaPlayerEntityFeature,
    MediaPlayerState,
    MediaType,
    async_process_play_media_url,
)
from homeassistant.config_entries import SOURCE_HASSIO, ConfigEntry
from homeassistant.const import CONF_NAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
import homeassistant.util.dt as dt_util

from .const import (
    DATA_AVAILABLE,
    DEFAULT_NAME,
    DOMAIN,
    LOGGER,
    SCREAM_ROUTER_SERVER,
    SINKS,
)
from .scream_router import ScreamRouter

MAX_VOLUME = 1

_P = ParamSpec("_P")


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up the ScreamRouter. Query for all sinks and make a device for each."""
    # CONF_NAME is only present in imported YAML.
    name = entry.data.get(CONF_NAME) or DEFAULT_NAME
    sinks = hass.data[DOMAIN][entry.entry_id][SINKS]
    scream_router: ScreamRouter = hass.data[DOMAIN][entry.entry_id][
        SCREAM_ROUTER_SERVER
    ]
    available = hass.data[DOMAIN][entry.entry_id][DATA_AVAILABLE]
    scream_router_devices: list[ScreamRouterDevice] = []
    for sink in sinks:
        entry_id = f"{sink['name']}{sink['ip']}"
        scream_router_devices.append(
            ScreamRouterDevice(
                entry, entry_id, scream_router, f"{sink['name']}", available
            )
        )
    if len(scream_router_devices) > 0:
        async_add_entities(scream_router_devices, True)


class ScreamRouterDevice(MediaPlayerEntity):
    """Representation of a ScreamRouter Sink."""

    _attr_has_entity_name = True
    _attr_name = None
    _attr_media_content_type = MediaType.MUSIC
    _attr_supported_features = (
        MediaPlayerEntityFeature.CLEAR_PLAYLIST
        | MediaPlayerEntityFeature.PLAY
        | MediaPlayerEntityFeature.PLAY_MEDIA
        | MediaPlayerEntityFeature.STOP
        | MediaPlayerEntityFeature.VOLUME_MUTE
        | MediaPlayerEntityFeature.VOLUME_SET
        | MediaPlayerEntityFeature.BROWSE_MEDIA
    )
    _volume_bkp: float = 0.0

    def __init__(
        self,
        config_entry: ConfigEntry,
        entry_id: str,
        scream_router: ScreamRouter,
        name: str,
        available: bool,
    ) -> None:
        """Initialize the ScreamRouter device."""
        self._config_entry = config_entry
        config_entry_id = entry_id
        self._scream_router = scream_router
        self._attr_available = available
        self._attr_unique_id = config_entry_id
        self._attr_device_info = DeviceInfo(
            entry_type=DeviceEntryType.SERVICE,
            identifiers={(DOMAIN, config_entry_id)},
            manufacturer="ScreamRouter",
            name=name,
        )
        self.name = name
        self._using_addon = config_entry.source == SOURCE_HASSIO

    async def async_update(self) -> None:
        """Get the latest details from the device."""
        if not self.available:
            return

        self._attr_state = MediaPlayerState.IDLE
        self._attr_available = True

        status = await self._scream_router.get_sinks()
        for sink in status:
            if sink["name"] == self.name:
                LOGGER.debug("Status: %s", sink)

                self._attr_volume_level = sink["volume"] / MAX_VOLUME
                if sink["enabled"]:
                    self._attr_state = MediaPlayerState.PLAYING
                else:
                    self._attr_state = MediaPlayerState.IDLE

    async def async_mute_volume(self, mute: bool) -> None:
        """Mute the volume."""
        assert self._attr_volume_level is not None
        if mute:
            self._volume_bkp = self._attr_volume_level
            await self.async_set_volume_level(0)
        else:
            await self.async_set_volume_level(self._volume_bkp)

        self._attr_is_volume_muted = mute

    async def async_set_volume_level(self, volume: float) -> None:
        """Set volume level, range 0..1."""
        await self._scream_router.change_sink_volume(
            f"{self.name}", volume * MAX_VOLUME
        )
        self._attr_volume_level = volume

        if self.is_volume_muted and self.volume_level > 0:
            # This can happen if we were muted and then see a volume_up.
            self._attr_is_volume_muted = False

    async def async_media_play(self) -> None:
        """Send play command."""
        await self._scream_router.enable_sink(f"{self.name}")
        self._attr_state = MediaPlayerState.PLAYING

    async def async_media_pause(self) -> None:
        """Send pause command."""
        await self._scream_router.disable_sink(f"{self.name}")
        self._attr_state = MediaPlayerState.IDLE

    async def async_media_stop(self) -> None:
        """Send stop command."""
        await self._scream_router.disable_sink(f"{self.name}")
        self._attr_state = MediaPlayerState.IDLE

    async def async_play_media(
        self, media_type: MediaType | str, media_id: str, **kwargs: Any
    ) -> None:
        """Play media from a URL or file."""
        # Handle media_source
        if media_source.is_media_source_id(media_id):
            sourced_media = await media_source.async_resolve_media(
                self.hass, media_id, self.entity_id
            )
            media_id = sourced_media.url

        # If media ID is a relative URL, we serve it from HA.
        media_id = async_process_play_media_url(
            self.hass, media_id, for_supervisor_network=True
        )

        await self._scream_router.play_url(f"{self.name}", media_id)
        self._attr_state = MediaPlayerState.PLAYING

    async def async_browse_media(
        self,
        media_content_type: MediaType | str | None = None,
        media_content_id: str | None = None,
    ) -> BrowseMedia:
        """Implement the websocket media browsing helper."""
        return await media_source.async_browse_media(self.hass, media_content_id)
