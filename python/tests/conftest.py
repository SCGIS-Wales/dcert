"""Fixtures shared by the test modules."""

from __future__ import annotations

import os
from dataclasses import replace

import pytest

from dcert.resilience import ResilienceConfig, resilience_config_from_env


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every ``DCERT_*`` variable so tests see the packaged defaults."""
    for name in list(os.environ):
        if name.startswith("DCERT_"):
            monkeypatch.delenv(name)


@pytest.fixture
def config(clean_env: None) -> ResilienceConfig:
    """The default resilience settings with backoff delays set to zero."""
    return replace(resilience_config_from_env(), retry_base_delay=0.0, retry_max_delay=0.0)
