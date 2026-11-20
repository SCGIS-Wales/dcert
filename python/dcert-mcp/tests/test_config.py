"""Tests for dcert_mcp.config."""

from pathlib import Path

import pytest
import yaml

from dcert_mcp.config import (
    Config,
    load_config,
    parse_config,
    read_config_file,
)


def test_load_config_is_cached():
    assert load_config() is load_config()
    assert isinstance(load_config(), Config)


def test_binaries_section():
    cfg = load_config()
    assert cfg.binaries.env == {"dcert": "DCERT_PATH", "dcert-mcp": "DCERT_MCP_BINARY"}
    assert cfg.binaries.fallback_env == "DCERT_MCP_BINARY"
    assert cfg.binaries.wrapper_probe_bytes == 128


def test_resilience_and_tools_defaults():
    cfg = load_config()
    assert cfg.resilience.bulkhead_max == 10
    assert cfg.resilience.max_response_bytes == 256 * 1024
    assert cfg.resilience.connect_timeout > 0
    assert cfg.resilience.truncation_lookback_chars == 200
    assert cfg.tools.truststore_password
    assert cfg.tools.expiry_days == 30
    assert cfg.tools.output_dir == "."
    assert cfg.server.port == 8080
    assert cfg.server.default_transport in cfg.server.transports
    assert cfg.otel.exporter in cfg.otel.exporters


def _raw() -> dict:
    with Path(load_config.__wrapped__.__code__.co_filename).with_name("config.yaml").open() as fh:
        return yaml.safe_load(fh)


def test_parse_config_round_trip():
    assert parse_config(_raw()) == load_config()


def test_parse_config_missing_section():
    raw = _raw()
    del raw["binaries"]
    with pytest.raises(ValueError, match="section 'binaries'"):
        parse_config(raw)


def test_parse_config_missing_key():
    raw = _raw()
    del raw["resilience"]["bulkhead_max"]
    with pytest.raises(ValueError, match="missing key"):
        parse_config(raw)


def test_parse_config_bad_string_list():
    raw = _raw()
    raw["server"]["transports"] = "stdio"
    with pytest.raises(ValueError, match="transports"):
        parse_config(raw)


def test_parse_config_bad_string_mapping():
    raw = _raw()
    raw["binaries"]["env"] = ["DCERT_PATH"]
    with pytest.raises(ValueError, match="'env' must be a mapping of strings"):
        parse_config(raw)


@pytest.mark.parametrize(
    ("section", "key", "match"),
    [("server", "default_transport", "default_transport"), ("otel", "exporter", "'exporter'")],
)
def test_parse_config_choice_must_be_listed(section, key, match):
    raw = _raw()
    raw[section][key] = "carrier-pigeon"
    with pytest.raises(ValueError, match=match):
        parse_config(raw)


def test_read_config_file(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(_raw()))
    assert read_config_file(path) == load_config()


def test_read_config_file_not_mapping(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("- just\n- a list\n")
    with pytest.raises(ValueError, match="top level must be a mapping"):
        read_config_file(path)
