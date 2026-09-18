"""Tests for dcert.config."""

from pathlib import Path

import pytest
import yaml

from dcert.config import (
    Config,
    PlatformTarget,
    archive_name_for,
    find_platform,
    load_config,
    parse_config,
    read_config_file,
)


def test_load_config_is_cached():
    assert load_config() is load_config()
    assert isinstance(load_config(), Config)


def test_platform_table():
    cfg = load_config()
    assert len(cfg.platforms) == 4
    assert {row.triple for row in cfg.platforms} == {
        "x86_64-unknown-linux-gnu",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
    }


@pytest.mark.parametrize(
    ("system", "machine", "triple"),
    [
        ("Linux", "x86_64", "x86_64-unknown-linux-gnu"),
        ("Darwin", "arm64", "aarch64-apple-darwin"),
        ("Darwin", "x86_64", "x86_64-apple-darwin"),
        ("Windows", "AMD64", "x86_64-pc-windows-msvc"),
    ],
)
def test_find_platform(system, machine, triple):
    target = find_platform(system, machine)
    assert target is not None
    assert target.triple == triple


def test_find_platform_unsupported():
    assert find_platform("Linux", "aarch64") is None
    assert find_platform("FreeBSD", "x86_64") is None


def test_archive_name_for():
    target = PlatformTarget("windows", "amd64", "x86_64-pc-windows-msvc", "zip", "win_amd64")
    assert archive_name_for(target) == "dcert-x86_64-pc-windows-msvc.zip"


def test_release_and_download_sections():
    cfg = load_config()
    assert "{version}" in cfg.release.url_template
    assert "{archive_name}" in cfg.release.url_template
    assert "github.com" in cfg.release.allowed_hosts
    assert cfg.download.max_bytes > 0
    assert cfg.download.timeout_seconds > 0
    assert cfg.binaries == {"dcert": "DCERT_PATH", "dcert-mcp": "DCERT_MCP_BINARY"}


def test_resilience_and_tools_defaults():
    cfg = load_config()
    assert cfg.resilience.bulkhead_max == 10
    assert cfg.resilience.max_response_bytes == 256 * 1024
    assert cfg.tools.truststore_password
    assert cfg.tools.expiry_days == 30
    assert cfg.server.port == 8080


def _raw() -> dict:
    with Path(load_config.__wrapped__.__code__.co_filename).with_name("config.yaml").open() as fh:
        return yaml.safe_load(fh)


def test_parse_config_round_trip():
    assert parse_config(_raw()) == load_config()


def test_parse_config_missing_section():
    raw = _raw()
    del raw["release"]
    with pytest.raises(ValueError, match="section 'release'"):
        parse_config(raw)


def test_parse_config_missing_key():
    raw = _raw()
    del raw["download"]["max_bytes"]
    with pytest.raises(ValueError, match="missing key"):
        parse_config(raw)


def test_parse_config_platforms_not_list():
    raw = _raw()
    raw["platforms"] = {}
    with pytest.raises(ValueError, match="'platforms'"):
        parse_config(raw)


def test_parse_config_bad_string_list():
    raw = _raw()
    raw["release"]["allowed_hosts"] = "github.com"
    with pytest.raises(ValueError, match="allowed_hosts"):
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
