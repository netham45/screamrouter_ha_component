"""Config flow for ScreamRouter integration."""

from __future__ import annotations

import logging
from typing import Any

from .scream_router import ScreamRouter
import voluptuous as vol

from homeassistant.components.hassio import HassioServiceInfo
from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_URL
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

SCHEMA = vol.Schema({vol.Required(CONF_URL, description="URL for ScreamRouter"): str})

async def scream_connect(url: str) -> None:
    """Connect to Scream and query the available sources."""
    scream_router: ScreamRouter = ScreamRouter(url)
    scream_router.get_sinks()

async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> None:
    """Validate the provided URL allows us to connect."""
    await scream_connect(data[CONF_URL])


class ScreamRouterConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Scream Router."""

    VERSION = 1
    entry: ConfigEntry | None = None
    hassio_discovery: dict[str, Any] | None = None

    async def async_step_user(self, user_input: dict[str, Any] | None = None
                              ) -> ConfigFlowResult:
        """Handle the initial step."""
        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=SCHEMA)

        self._async_abort_entries_match({CONF_URL: user_input[CONF_URL]})

        errors = {}

        try:
            await scream_connect(user_input[CONF_URL])
        except Exception as e:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception %s", e)
            errors["base"] = f"unknown {e}"
        else:
            return self.async_create_entry(title=user_input[CONF_URL], data=user_input)

        return self.async_show_form(step_id="user", data_schema=SCHEMA, errors=errors)

    async def async_step_hassio(self, discovery_info: HassioServiceInfo
                                ) -> ConfigFlowResult:
        """Handle the discovery step via hassio."""
        await self.async_set_unique_id("hassio")
        self._abort_if_unique_id_configured(discovery_info.config)

        self.hassio_discovery = discovery_info.config
        self.context["title_placeholders"] = {"url": discovery_info.config[CONF_URL]}
        return await self.async_step_hassio_confirm()

    async def async_step_hassio_confirm(self, user_input: dict[str, Any] | None = None
                                        ) -> ConfigFlowResult:
        """Confirm Supervisor discovery."""
        assert self.hassio_discovery
        if user_input is None:
            return self.async_show_form(step_id="hassio_confirm",
                description_placeholders={"addon": self.hassio_discovery["addon"]})

        self.hassio_discovery.pop("addon")

        try:
            await scream_connect(user_input[CONF_URL])
        except Exception as e:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception %s", e)
            return self.async_abort(reason="unknown")

        return self.async_create_entry(title=user_input[CONF_URL], data=self.hassio_discovery)