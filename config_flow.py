"""Config flow for ScreamRouter integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.components.hassio import HassioServiceInfo
from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_URL, CONF_UUID
from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo

from .const import DOMAIN
from .mdns import DiscoveredServer, async_discover_mdns, normalize_uuid
from .scream_router import ScreamRouter

_LOGGER = logging.getLogger(__name__)

DISCOVERED_SERVER = "discovered_server"
MANUAL_SELECTION = "__manual__"
MANUAL_SELECTION_LABEL = "Manually enter URL"

async def scream_connect(url: str) -> None:
    """Connect to Scream and query the available sources."""
    scream_router: ScreamRouter = ScreamRouter(url)
    await scream_router.get_sinks()


def _format_choice(display_name: str, url: str) -> str:
    """Return a human-friendly entry for a discovered server."""
    return f"{display_name} ({url})"


class ScreamRouterConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Scream Router."""

    VERSION = 1
    entry: ConfigEntry | None = None
    hassio_discovery: dict[str, Any] | None = None

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._discovered_servers: dict[str, DiscoveredServer] = {}
        self._previous_discovered: dict[str, DiscoveredServer] = {}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            selection = user_input.get(DISCOVERED_SERVER)
            manual_url = (user_input.get(CONF_URL) or "").strip()

            url: str | None = None
            selected_data: DiscoveredServer | None = None
            if selection == MANUAL_SELECTION or not self._previous_discovered:
                if not manual_url:
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
                match_data: dict[str, str] = {CONF_URL: url}
                uuid: str | None = None
                if selected_data:
                    uuid = selected_data.get("uuid")
                    if uuid:
                        match_data[CONF_UUID] = uuid

                self._async_abort_entries_match(match_data)
                try:
                    await scream_connect(url)
                except Exception:  # pylint: disable=broad-except
                    _LOGGER.exception("Unexpected exception while connecting to %s", url)
                    errors["base"] = "cannot_connect"
                else:
                    entry_data: dict[str, str] = {CONF_URL: url}
                    if uuid:
                        entry_data[CONF_UUID] = uuid
                    return self.async_create_entry(title=url, data=entry_data)

        discoveries = await async_discover_mdns()
        self._discovered_servers = discoveries
        self._previous_discovered = dict(discoveries)

        data_schema = self._build_user_schema()

        return self.async_show_form(
            step_id="user",
            data_schema=data_schema,
            errors=errors,
        )

    def _build_user_schema(self) -> vol.Schema:
        """Construct the schema shown to the user."""
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
            fields[vol.Required(DISCOVERED_SERVER, default=default_choice)] = vol.In(choices)
            fields[vol.Optional(CONF_URL, description="URL for ScreamRouter")] = str
        else:
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
        return await self.async_step_hassio_confirm()

    async def async_step_hassio_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm Supervisor discovery."""
        assert self.hassio_discovery
        if user_input is None:
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

        return self.async_create_entry(
            title=user_input[CONF_URL], data=self.hassio_discovery
        )

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

        return await self.async_step_user()
