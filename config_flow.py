"""Config flow for ScreamRouter integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.components.hassio import HassioServiceInfo
from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_URL, CONF_UUID
from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo

from .const import DOMAIN, SESSION_STORE
from .mdns import DiscoveredServer, async_discover_mdns, normalize_uuid
from .scream_router import ScreamRouter
from .session_store import SessionStore

_LOGGER = logging.getLogger(__name__)

DISCOVERED_SERVER = "discovered_server"
MANUAL_SELECTION = "__manual__"
MANUAL_SELECTION_LABEL = "Manually enter URL"

async def scream_connect(url: str) -> None:
    """Connect to Scream and query the available sources."""
    _LOGGER.debug("scream_connect: attempting connection to %s", url)
    scream_router: ScreamRouter = ScreamRouter(url)
    await scream_router.get_sinks()
    _LOGGER.debug("scream_connect: successfully queried sinks for %s", url)


def _format_choice(display_name: str, url: str) -> str:
    """Return a human-friendly entry for a discovered server."""
    return f"{display_name} ({url})"


class ScreamRouterConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Scream Router.
    
    This flow supports multiple discovery methods:
    - Home Assistant's native zeroconf discovery
    - Manual mDNS scanning
    - Manual URL entry
    
    When zeroconf discovers a server and redirects to the user step,
    the discovery info is preserved and merged with any additional
    mDNS discoveries, with zeroconf info taking precedence.
    """

    VERSION = 1
    entry: ConfigEntry | None = None
    hassio_discovery: dict[str, Any] | None = None

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._discovered_servers: dict[str, DiscoveredServer] = {}
        self._previous_discovered: dict[str, DiscoveredServer] = {}
        self._session_store: SessionStore | None = None
        _LOGGER.debug("ScreamRouterConfigFlow initialized")

    async def _async_get_session_store(self) -> SessionStore:
        if self._session_store is None:
            _LOGGER.debug(
                "_async_get_session_store: creating SessionStore for domain data"
            )
            domain_data = self.hass.data.setdefault(DOMAIN, {})
            self._session_store = domain_data.setdefault(
                SESSION_STORE, SessionStore(self.hass)
            )
            await self._session_store.async_load()
        else:
            _LOGGER.debug("_async_get_session_store: reusing existing SessionStore")
        return self._session_store

    def _merge_discoveries(
        self,
        ha_discoveries: dict[str, DiscoveredServer],
        mdns_discoveries: dict[str, DiscoveredServer],
    ) -> dict[str, DiscoveredServer]:
        """Merge Home Assistant and mDNS discoveries, preferring HA's info.
        
        When Home Assistant's zeroconf discovery finds a server and passes it
        to the user step, we want to preserve that discovery info while also
        enriching the list with any additional servers found via mDNS scanning.
        
        Priority rules:
        1. HA discoveries always take precedence for URL conflicts
        2. HA discoveries always take precedence for UUID conflicts
        3. mDNS discoveries are added only if they don't conflict
        
        Args:
            ha_discoveries: Servers discovered via Home Assistant's zeroconf
            mdns_discoveries: Servers discovered via manual mDNS scan
            
        Returns:
            Merged dictionary with HA discoveries taking precedence
            
        Example:
            HA discovers server with UUID 'abc' at 192.168.1.100
            mDNS discovers same UUID at 192.168.1.101 (IP changed)
            Result: Uses HA's 192.168.1.100 (more reliable)
        """
        _LOGGER.debug(
            "_merge_discoveries: ha_count=%d mdns_count=%d",
            len(ha_discoveries),
            len(mdns_discoveries),
        )
        merged: dict[str, DiscoveredServer] = {}
        
        # Track UUIDs from HA discoveries to prevent duplicates
        ha_uuids: set[str] = set()
        for data in ha_discoveries.values():
            uuid = data.get("uuid")
            if uuid:
                normalized = normalize_uuid(uuid)
                if normalized:
                    ha_uuids.add(normalized)
        
        # Add all HA discoveries first (highest priority)
        merged.update(ha_discoveries)
        
        # Add mDNS discoveries that don't conflict
        for url, data in mdns_discoveries.items():
            # Skip if URL already exists (HA takes precedence)
            if url in merged:
                _LOGGER.debug(
                    "_merge_discoveries: skipping mDNS url=%s (URL conflict with HA)",
                    url,
                )
                continue
            
            # Skip if UUID already exists in HA discoveries
            mdns_uuid = data.get("uuid")
            if mdns_uuid:
                normalized = normalize_uuid(mdns_uuid)
                if normalized and normalized in ha_uuids:
                    _LOGGER.debug(
                        "_merge_discoveries: skipping mDNS url=%s uuid=%s (UUID conflict with HA)",
                        url,
                        normalized,
                    )
                    continue
            
            # Add new discovery
            _LOGGER.debug("_merge_discoveries: adding mDNS discovery url=%s", url)
            merged[url] = data
        
        _LOGGER.debug("_merge_discoveries: final merged_count=%d", len(merged))
        return merged

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        _LOGGER.debug("async_step_user: received input=%s", user_input)
        errors: dict[str, str] = {}

        if user_input is not None:
            selection = user_input.get(DISCOVERED_SERVER)
            manual_url = (user_input.get(CONF_URL) or "").strip()
            _LOGGER.debug(
                "async_step_user: selection=%s manual_url=%s discovered_count=%d",
                selection,
                manual_url,
                len(self._previous_discovered),
            )

            url: str | None = None
            selected_data: DiscoveredServer | None = None
            if selection == MANUAL_SELECTION or not self._previous_discovered:
                if not manual_url:
                    _LOGGER.debug("async_step_user: manual selection without URL")
                    errors[CONF_URL] = "manual_url_required"
                else:
                    url = manual_url
            elif selection:
                url = selection
                selected_data = self._previous_discovered.get(url)
            elif manual_url:
                url = manual_url
            else:
                errors["base"] = "no_server_selected"

            if url and not errors:
                match_data: dict[str, str] = {}
                uuid: str | None = None
                if selected_data:
                    _LOGGER.debug("async_step_user: selected data=%s", selected_data)
                    uuid = selected_data.get("uuid")
                normalized_uuid = normalize_uuid(uuid) if uuid else None
                if normalized_uuid:
                    match_data[CONF_UUID] = normalized_uuid
                    _LOGGER.debug(
                        "async_step_user: attempting to match existing entry by uuid=%s",
                        normalized_uuid,
                    )
                else:
                    match_data[CONF_URL] = url
                    _LOGGER.debug(
                        "async_step_user: attempting to match existing entry by url=%s",
                        url,
                    )

                self._async_abort_entries_match(match_data)
                try:
                    await scream_connect(url)
                except Exception:  # pylint: disable=broad-except
                    _LOGGER.exception("Unexpected exception while connecting to %s", url)
                    errors["base"] = "cannot_connect"
                else:
                    entry_data: dict[str, str] = {}
                    if normalized_uuid:
                        entry_data[CONF_UUID] = normalized_uuid
                        session_store = await self._async_get_session_store()
                        await session_store.async_set(normalized_uuid, url)
                        _LOGGER.debug(
                            "async_step_user: stored url=%s for uuid=%s", url, normalized_uuid
                        )
                    else:
                        entry_data[CONF_URL] = url
                        _LOGGER.debug(
                            "async_step_user: creating entry without uuid, url=%s", url
                        )
                    return self.async_create_entry(title=url, data=entry_data)

        # Preserve any existing discoveries from Home Assistant's zeroconf.
        # This ensures that when zeroconf discovery redirects to the user step,
        # we don't lose the discovery info by performing a fresh mDNS scan.
        ha_discoveries = dict(self._discovered_servers)

        # Perform mDNS scan to find additional servers
        mdns_discoveries = await async_discover_mdns(self.hass)

        # Merge discoveries with priority to Home Assistant's zeroconf info.
        # This prevents the second discovery stage from overwriting HA's data
        # while still allowing additional servers to be discovered.
        merged_discoveries = self._merge_discoveries(ha_discoveries, mdns_discoveries)

        self._discovered_servers = merged_discoveries
        self._previous_discovered = dict(merged_discoveries)
        _LOGGER.debug(
            "async_step_user: merged discoveries ha_count=%d mdns_count=%d final_count=%d",
            len(ha_discoveries),
            len(mdns_discoveries),
            len(merged_discoveries),
        )

        data_schema = self._build_user_schema()

        return self.async_show_form(
            step_id="user",
            data_schema=data_schema,
            errors=errors,
        )

    def _build_user_schema(self) -> vol.Schema:
        """Construct the schema shown to the user."""
        _LOGGER.debug(
            "_build_user_schema: building schema for %d discovered servers",
            len(self._discovered_servers),
        )
        fields: dict[Any, Any] = {}
        if self._discovered_servers:
            choices: dict[str, str] = {
                url: _format_choice(data["name"], url)
                for url, data in sorted(
                    self._discovered_servers.items(),
                    key=lambda item: (item[1]["name"], item[0]),
                )
            }
            choices[MANUAL_SELECTION] = MANUAL_SELECTION_LABEL
            default_choice = next(iter(self._discovered_servers)) if self._discovered_servers else MANUAL_SELECTION
            _LOGGER.debug(
                "_build_user_schema: default_choice=%s choices=%s",
                default_choice,
                choices,
            )
            fields[vol.Required(DISCOVERED_SERVER, default=default_choice)] = vol.In(choices)
            fields[vol.Optional(CONF_URL, description="URL for ScreamRouter")] = str
        else:
            _LOGGER.debug("_build_user_schema: no discoveries, requiring manual URL")
            fields[vol.Required(CONF_URL, description="URL for ScreamRouter")] = str
        return vol.Schema(fields)

    async def async_step_hassio(
        self, discovery_info: HassioServiceInfo
    ) -> ConfigFlowResult:
        """Handle the discovery step via hassio."""
        await self.async_set_unique_id("hassio")
        self._abort_if_unique_id_configured(discovery_info.config)

        self.hassio_discovery = discovery_info.config
        self.context["title_placeholders"] = {"url": discovery_info.config[CONF_URL]}
        _LOGGER.debug(
            "async_step_hassio: discovery_info=%s", discovery_info.config
        )
        return await self.async_step_hassio_confirm()

    async def async_step_hassio_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm Supervisor discovery."""
        assert self.hassio_discovery
        if user_input is None:
            _LOGGER.debug(
                "async_step_hassio_confirm: awaiting user confirmation for %s",
                self.hassio_discovery,
            )
            return self.async_show_form(
                step_id="hassio_confirm",
                description_placeholders={"addon": self.hassio_discovery["addon"]},
            )

        self.hassio_discovery.pop("addon")

        try:
            await scream_connect(user_input[CONF_URL])
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception(
                "Unexpected exception while connecting to %s", user_input[CONF_URL]
            )
            return self.async_abort(reason="cannot_connect")

        entry_data = dict(self.hassio_discovery)
        uuid = normalize_uuid(entry_data.get(CONF_UUID))
        url = user_input[CONF_URL]
        _LOGGER.debug(
            "async_step_hassio_confirm: normalized_uuid=%s url=%s", uuid, url
        )
        if uuid:
            session_store = await self._async_get_session_store()
            await session_store.async_set(uuid, url)
            entry_data[CONF_UUID] = uuid
            entry_data.pop(CONF_URL, None)
        else:
            entry_data[CONF_URL] = url
        return self.async_create_entry(title=url, data=entry_data)

    async def async_step_zeroconf(
        self, discovery_info: ZeroconfServiceInfo
    ) -> ConfigFlowResult:
        """Handle Zeroconf discovery."""
        properties = discovery_info.properties or {}
        uuid = normalize_uuid(properties.get("uuid"))
        host = discovery_info.host
        port = discovery_info.port or 80
        host_for_url = host
        if ":" in host and not host.startswith("["):
            host_for_url = f"[{host}]"
        url = f"https://{host_for_url}:{port}"
        service_name = discovery_info.name.rstrip(".")
        _LOGGER.debug(
            "async_step_zeroconf: service=%s host=%s port=%s uuid=%s url=%s",
            service_name,
            host,
            port,
            uuid,
            url,
        )

        match_data: dict[str, str] = {CONF_URL: url}
        if uuid:
            match_data[CONF_UUID] = uuid

        self._async_abort_entries_match(match_data)

        discovered: DiscoveredServer = {"name": service_name}
        if uuid:
            discovered["uuid"] = uuid

        discovered_map = {url: discovered}
        self._discovered_servers = discovered_map
        self._previous_discovered = dict(discovered_map)
        self.context["title_placeholders"] = {"name": service_name, "url": url}

        if uuid:
            session_store = await self._async_get_session_store()
            await session_store.async_set(uuid, url)

        return await self.async_step_user()
