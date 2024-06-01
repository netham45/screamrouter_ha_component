"""The Scream Router integration."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_URL, Platform
from homeassistant.core import HomeAssistant

from .const import DATA_AVAILABLE, DOMAIN, LOGGER, SCREAM_ROUTER_SERVER, SINKS
from .scream_router import ScreamRouter

PLATFORMS = [Platform.MEDIA_PLAYER]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Scream Router from a config entry."""
    config = entry.data

    url = config[CONF_URL]
    scream_router: ScreamRouter = ScreamRouter(url)
    LOGGER.warning(hass.data)
    available = True
    try:
        sinks: dict = await scream_router.get_sinks()
        LOGGER.warning(sinks)
    except Exception as exc:
        LOGGER.warning("Failed to query Scream Router %s", exc)
        available = False
        return available

    domain_data = hass.data.setdefault(DOMAIN, {})
    domain_data[entry.entry_id] = {
        SINKS: sinks,
        DATA_AVAILABLE: available,
        SCREAM_ROUTER_SERVER: scream_router,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        entry_data = hass.data[DOMAIN].pop(entry.entry_id)
    # vlc = entry_data[SINKS]

    # await disconnect_vlc(vlc)

    return unload_ok


async def disconnect_scream_router(scream_router: ScreamRouter) -> None:
    """Disconnect from ScreamRouter."""
    LOGGER.debug("Disconnecting from ScreamRouter")
