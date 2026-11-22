"""Config flow for the Home Tunnel status integration."""
import aiohttp
import probatio
from homeassistant.config_entries import ConfigFlowResult
from homeassistant import config_entries
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers import selector

from .const import CONF_HOST, CONF_PORT, CONF_TOKEN, DEFAULT_PORT, DOMAIN
from .coordinator import validate_endpoint


class HomeTunnelConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Set up the metrics connection from the HA UI."""

    VERSION = 1

    async def async_step_reconfigure(self, user_input=None) -> ConfigFlowResult:
        entry = self._get_reconfigure_entry()
        errors = {}
        if user_input is not None:
            token = user_input[CONF_TOKEN]
            if not isinstance(token, str) or len(token) != 64 or any(c not in "0123456789abcdef" for c in token):
                errors[CONF_TOKEN] = "invalid_token"
            else:
                try:
                    await self._validate_connection(entry.data[CONF_HOST], entry.data[CONF_PORT], token)
                except InvalidToken:
                    errors[CONF_TOKEN] = "invalid_token"
                except CannotConnect:
                    errors["base"] = "cannot_connect"
                else:
                    return self.async_update_reload_and_abort(
                        entry,
                        data_updates={CONF_TOKEN: token},
                    )

        schema = probatio.Schema({
            probatio.Required(probatio.Secret(CONF_TOKEN)): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
        })
        return self.async_show_form(step_id="reconfigure", data_schema=schema, errors=errors)

    async def async_step_user(self, user_input=None) -> ConfigFlowResult:
        errors = {}
        if user_input is not None:
            try:
                port_value = user_input.get(CONF_PORT, DEFAULT_PORT)
                if isinstance(port_value, float) and port_value.is_integer():
                    port_value = int(port_value)
                host, port = validate_endpoint(user_input[CONF_HOST], port_value)
                token = user_input[CONF_TOKEN]
                if not isinstance(token, str) or len(token) != 64 or any(c not in "0123456789abcdef" for c in token):
                    errors[CONF_TOKEN] = "invalid_token"
                else:
                    await self._validate_connection(host, port, token)
                    await self.async_set_unique_id(f"{host}:{port}")
                    self._abort_if_unique_id_configured()
                    return self.async_create_entry(
                        title="Home Tunnel",
                        data={CONF_HOST: host, CONF_PORT: port, CONF_TOKEN: token},
                    )
            except ValueError:
                errors[CONF_HOST] = "invalid_host"
            except InvalidToken:
                errors[CONF_TOKEN] = "invalid_token"
            except CannotConnect:
                errors["base"] = "cannot_connect"

        schema = probatio.Schema({
            probatio.Required(CONF_HOST): selector.TextSelector(),
            probatio.Optional(CONF_PORT, default=DEFAULT_PORT): selector.NumberSelector(
                selector.NumberSelectorConfig(min=1, max=65535, mode=selector.NumberSelectorMode.BOX)
            ),
            probatio.Required(probatio.Secret(CONF_TOKEN)): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
        })
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def _validate_connection(self, host: str, port: int, token: str) -> None:
        session = async_get_clientsession(self.hass)
        try:
            async with session.get(
                f"http://{host}:{port}/metrics",
                headers={"Authorization": f"Bearer {token}"},
                timeout=aiohttp.ClientTimeout(total=5),
            ) as response:
                if response.status == 401:
                    raise InvalidToken
                response.raise_for_status()
                data = await response.json()
        except InvalidToken:
            raise
        except Exception as err:
            raise CannotConnect from err
        if not isinstance(data, dict) or not isinstance(data.get("version"), str):
            raise CannotConnect


class CannotConnect(Exception):
    """The Home Tunnel metrics endpoint could not be reached."""


class InvalidToken(Exception):
    """The metrics endpoint rejected the supplied token."""
