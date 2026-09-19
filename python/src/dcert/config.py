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
class ReleaseConfig:
    """Where release archives are downloaded from."""

    url_template: str
    allowed_hosts: tuple[str, ...]


@dataclass(frozen=True)
class DownloadConfig:
    """Limits applied while downloading a release archive."""

    timeout_seconds: float
    max_bytes: int
    chunk_size: int
    lock_file_name: str


@dataclass(frozen=True)
class PlatformTarget:
    """One supported (system, machine) pair and its release artefact."""

    system: str
    machine: str
    triple: str
    archive_extension: str
    wheel_tag: str


@dataclass(frozen=True)
class ServerConfig:
    """Defaults for the FastMCP proxy server."""

    name: str
    host: str
    port: int


@dataclass(frozen=True)
class ResilienceDefaults:
    """Baseline resilience values before environment overrides."""

    tool_timeout: float
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


@dataclass(frozen=True)
class OTelDefaults:
    """Baseline OpenTelemetry values before environment overrides."""

    service_name: str
    exporter: str


@dataclass(frozen=True)
class ToolsConfig:
    """Defaults applied by the typed tool wrappers."""

    truststore_password: str
    keystore_alias: str
    expiry_days: int


@dataclass(frozen=True)
class Config:
    """The whole packaged configuration."""

    release: ReleaseConfig
    download: DownloadConfig
    binaries: Mapping[str, str]
    platforms: tuple[PlatformTarget, ...]
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


def _platforms(raw: object) -> tuple[PlatformTarget, ...]:
    """Build the platform table from the raw YAML list."""
    if not isinstance(raw, list) or not raw:
        raise ValueError("config.yaml: 'platforms' must be a non-empty list")
    return tuple(
        PlatformTarget(
            system=str(row["system"]).lower(),
            machine=str(row["machine"]).lower(),
            triple=str(row["triple"]),
            archive_extension=str(row["archive_extension"]),
            wheel_tag=str(row["wheel_tag"]),
        )
        for row in raw
    )


def parse_config(raw: Mapping[str, Any]) -> Config:
    """Convert a parsed YAML mapping into a :class:`Config` record.

    Raises:
        ValueError: If a required section or key is missing or malformed.
    """
    release = _section(raw, "release")
    download = _section(raw, "download")
    server = _section(raw, "server")
    resilience = _section(raw, "resilience")
    otel = _section(raw, "otel")
    tools = _section(raw, "tools")
    binaries = _section(raw, "binaries")
    try:
        return Config(
            release=ReleaseConfig(
                url_template=str(release["url_template"]),
                allowed_hosts=_string_tuple(release, "allowed_hosts"),
            ),
            download=DownloadConfig(
                timeout_seconds=float(download["timeout_seconds"]),
                max_bytes=int(download["max_bytes"]),
                chunk_size=int(download["chunk_size"]),
                lock_file_name=str(download["lock_file_name"]),
            ),
            binaries={str(key): str(value) for key, value in binaries.items()},
            platforms=_platforms(raw.get("platforms")),
            passthrough_env=_string_tuple(_section(raw, "subprocess"), "passthrough_env"),
            server=ServerConfig(
                name=str(server["name"]),
                host=str(server["host"]),
                port=int(server["port"]),
            ),
            resilience=ResilienceDefaults(
                tool_timeout=float(resilience["tool_timeout"]),
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
            ),
            otel=OTelDefaults(
                service_name=str(otel["service_name"]),
                exporter=str(otel["exporter"]),
            ),
            tools=ToolsConfig(
                truststore_password=str(tools["truststore_password"]),
                keystore_alias=str(tools["keystore_alias"]),
                expiry_days=int(tools["expiry_days"]),
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


def archive_name_for(target: PlatformTarget) -> str:
    """Return the release archive name for *target*."""
    return f"dcert-{target.triple}.{target.archive_extension}"


def find_platform(system: str, machine: str, config: Config | None = None) -> PlatformTarget | None:
    """Return the platform row matching *system* and *machine*, if supported."""
    cfg = config or load_config()
    key = (system.lower(), machine.lower())
    return next((row for row in cfg.platforms if (row.system, row.machine) == key), None)
