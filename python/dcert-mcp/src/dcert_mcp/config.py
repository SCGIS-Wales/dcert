"""Packaged configuration for the dcert Python wrapper.

All tunable values live in ``config.yaml`` next to this module. The file is
parsed once, validated and exposed as an immutable :class:`Config` record
through :func:`load_config`.
"""

from __future__ import annotations

import functools
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

CONFIG_PATH = Path(__file__).with_name("config.yaml")


@dataclass(frozen=True)
class BinariesConfig:
    """How the Rust binaries are located."""

    env: Mapping[str, str]
    fallback_env: str
    wrapper_probe_bytes: int


@dataclass(frozen=True)
class AuthConfig:
    """Where HTTP and SSE authentication settings come from."""

    token_env: str
    oidc_issuer_env: str
    oidc_audience_env: str
    oidc_jwks_env: str
    min_token_length: int


@dataclass(frozen=True)
class ServerConfig:
    """Defaults for the FastMCP proxy server."""

    name: str
    host: str
    port: int
    transports: tuple[str, ...]
    default_transport: str
    loopback_hosts: tuple[str, ...]
    auth: AuthConfig


@dataclass(frozen=True)
class ResilienceDefaults:
    """Baseline resilience values before environment overrides."""

    tool_timeout: float
    connect_timeout: float
    reconnect_max: int
    retry_max_attempts: int
    retry_base_delay: float
    retry_max_delay: float
    retry_multiplier: float
    circuit_breaker_threshold: int
    circuit_breaker_reset_timeout: float
    rate_limit_rps: float
    rate_limit_burst: int
    bulkhead_max: int
    cache_tool_ttl: int
    cache_list_ttl: int
    max_response_bytes: int
    truncation_lookback_chars: int


@dataclass(frozen=True)
class OTelDefaults:
    """Baseline OpenTelemetry values before environment overrides."""

    service_name: str
    exporter: str
    exporters: tuple[str, ...]


@dataclass(frozen=True)
class ToolsConfig:
    """Defaults applied by the typed tool wrappers."""

    truststore_password: str
    keystore_alias: str
    expiry_days: int
    output_dir: str


@dataclass(frozen=True)
class Config:
    """The whole packaged configuration."""

    binaries: BinariesConfig
    passthrough_env: tuple[str, ...]
    server: ServerConfig
    resilience: ResilienceDefaults
    otel: OTelDefaults
    tools: ToolsConfig


def _section(raw: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    """Return the mapping stored under *name* or raise a clear error."""
    value = raw.get(name)
    if not isinstance(value, Mapping):
        raise ValueError(f"config.yaml: section '{name}' is missing or not a mapping")
    return value


def _string_tuple(raw: Mapping[str, Any], name: str) -> tuple[str, ...]:
    """Return the list of strings stored under *name* as a tuple."""
    value = raw.get(name)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"config.yaml: '{name}' must be a list of strings")
    return tuple(value)


def _string_mapping(raw: Mapping[str, Any], name: str) -> dict[str, str]:
    """Return the mapping of strings stored under *name*."""
    value = raw.get(name)
    if not isinstance(value, Mapping) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        raise ValueError(f"config.yaml: '{name}' must be a mapping of strings")
    return dict(value)


def _member(value: str, choices: tuple[str, ...], name: str) -> str:
    """Return *value* after checking it is one of *choices*."""
    if value not in choices:
        raise ValueError(f"config.yaml: '{name}' must be one of {', '.join(choices)}")
    return value


def parse_config(raw: Mapping[str, Any]) -> Config:
    """Convert a parsed YAML mapping into a :class:`Config` record.

    Raises:
        ValueError: If a required section or key is missing or malformed.
    """
    server = _section(raw, "server")
    resilience = _section(raw, "resilience")
    otel = _section(raw, "otel")
    tools = _section(raw, "tools")
    binaries = _section(raw, "binaries")
    transports = _string_tuple(server, "transports")
    auth = _section(server, "auth")
    exporters = _string_tuple(otel, "exporters")
    try:
        return Config(
            binaries=BinariesConfig(
                env=_string_mapping(binaries, "env"),
                fallback_env=str(binaries["fallback_env"]),
                wrapper_probe_bytes=int(binaries["wrapper_probe_bytes"]),
            ),
            passthrough_env=_string_tuple(_section(raw, "subprocess"), "passthrough_env"),
            server=ServerConfig(
                name=str(server["name"]),
                host=str(server["host"]),
                port=int(server["port"]),
                transports=transports,
                default_transport=_member(
                    str(server["default_transport"]), transports, "default_transport"
                ),
                loopback_hosts=_string_tuple(server, "loopback_hosts"),
                auth=AuthConfig(
                    token_env=str(auth["token_env"]),
                    oidc_issuer_env=str(auth["oidc_issuer_env"]),
                    oidc_audience_env=str(auth["oidc_audience_env"]),
                    oidc_jwks_env=str(auth["oidc_jwks_env"]),
                    min_token_length=int(auth["min_token_length"]),
                ),
            ),
            resilience=ResilienceDefaults(
                tool_timeout=float(resilience["tool_timeout"]),
                connect_timeout=float(resilience["connect_timeout"]),
                reconnect_max=int(resilience["reconnect_max"]),
                retry_max_attempts=int(resilience["retry_max_attempts"]),
                retry_base_delay=float(resilience["retry_base_delay"]),
                retry_max_delay=float(resilience["retry_max_delay"]),
                retry_multiplier=float(resilience["retry_multiplier"]),
                circuit_breaker_threshold=int(resilience["circuit_breaker_threshold"]),
                circuit_breaker_reset_timeout=float(resilience["circuit_breaker_reset_timeout"]),
                rate_limit_rps=float(resilience["rate_limit_rps"]),
                rate_limit_burst=int(resilience["rate_limit_burst"]),
                bulkhead_max=int(resilience["bulkhead_max"]),
                cache_tool_ttl=int(resilience["cache_tool_ttl"]),
                cache_list_ttl=int(resilience["cache_list_ttl"]),
                max_response_bytes=int(resilience["max_response_bytes"]),
                truncation_lookback_chars=int(resilience["truncation_lookback_chars"]),
            ),
            otel=OTelDefaults(
                service_name=str(otel["service_name"]),
                exporter=_member(str(otel["exporter"]), exporters, "exporter"),
                exporters=exporters,
            ),
            tools=ToolsConfig(
                truststore_password=str(tools["truststore_password"]),
                keystore_alias=str(tools["keystore_alias"]),
                expiry_days=int(tools["expiry_days"]),
                output_dir=str(tools["output_dir"]),
            ),
        )
    except KeyError as exc:
        raise ValueError(f"config.yaml: missing key {exc}") from exc


def read_config_file(path: Path = CONFIG_PATH) -> Config:
    """Parse the YAML file at *path* into a :class:`Config` record."""
    with path.open("rb") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, Mapping):
        raise ValueError(f"{path}: top level must be a mapping")
    return parse_config(raw)


@functools.cache
def load_config() -> Config:
    """Return the packaged configuration, parsed once per process."""
    return read_config_file()
