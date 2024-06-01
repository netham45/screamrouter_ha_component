"""Config flow for VLC media player Telnet integration."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any

import voluptuous as vol

from homeassistant.components.hassio import HassioServiceInfo
from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_URL, CONF_NAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


def user_form_schema(user_input: dict[str, Any] | None) -> vol.Schema:
    """Return user form schema."""
    user_input = user_input or {}
    return vol.Schema(
        {
            vol.Required(CONF_URL, description="URL for ScreamRouter"): str
        }
    )


STEP_REAUTH_DATA_SCHEMA = vol.Schema({vol.Required(CONF_URL): str})


async def scream_connect(scream_router_info: dict) -> None:
    """Connect to Scream and query the available sources."""


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, str]:
    """Validate the user input allows us to connect."""
    scream_router_info: dict = {
        "url": data[CONF_URL],
    }

    try:
        await scream_connect(scream_router_info)
    except Exception as e:
        raise Exception from e
    # except ConnectError as err:
    #    raise CannotConnect from err
    # except AuthError as err:
    #    raise InvalidAuth from err

    # CONF_NAME is only present in the imported YAML data.
    return {"title": data[CONF_URL]}


class ScreamRouterConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Scream Router."""

    VERSION = 1
    entry: ConfigEntry | None = None
    hassio_discovery: dict[str, Any] | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        if user_input is None:
            return self.async_show_form(
                step_id="user", data_schema=user_form_schema(user_input)
            )

        self._async_abort_entries_match(
            {CONF_URL: user_input[CONF_URL]}
        )

        errors = {}

        try:
            info = await validate_input(self.hass, user_input)
        except CannotConnect:
            errors["base"] = "cannot_connect"
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception")
            errors["base"] = "unknown"
        else:
            return self.async_create_entry(title=info["title"], data=user_input)

        return self.async_show_form(
            step_id="user", data_schema=user_form_schema(user_input), errors=errors
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Handle reauth flow."""
        self.entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        assert self.entry
        self.context["title_placeholders"] = {"url": self.entry.data[CONF_URL]}
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle reauth confirm."""
        assert self.entry
        errors = {}

        if user_input is not None:
            try:
                await validate_input(self.hass, {**self.entry.data, **user_input})
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                self.hass.config_entries.async_update_entry(
                    self.entry,
                    data={
                        **self.entry.data,
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                    },
                )
                self.hass.async_create_task(
                    self.hass.config_entries.async_reload(self.entry.entry_id)
                )
                return self.async_abort(reason="reauth_successful")

        return self.async_show_form(
            step_id="reauth_confirm",
            description_placeholders={CONF_URL: self.entry.data[CONF_URL]},
            data_schema=STEP_REAUTH_DATA_SCHEMA,
            errors=errors,
        )

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
            info = await validate_input(self.hass, self.hassio_discovery)
        except CannotConnect:
            return self.async_abort(reason="cannot_connect")
        except InvalidAuth:
            return self.async_abort(reason="invalid_auth")
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception")
            return self.async_abort(reason="unknown")

        return self.async_create_entry(title=info["title"], data=self.hassio_discovery)


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
