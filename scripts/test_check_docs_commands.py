"""Tests for scripts/check_docs_commands.py, with fixture help text (no binaries)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_PATH = Path(__file__).with_name("check_docs_commands.py")
_SPEC = importlib.util.spec_from_file_location("check_docs_commands", _PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
cdc = importlib.util.module_from_spec(_SPEC)
sys.modules["check_docs_commands"] = cdc
_SPEC.loader.exec_module(cdc)

TOP_HELP = """\
TLS certificate tool.

Usage: dcert <COMMAND>

Commands:
  check     Analyze certificates (default command)
  diagnose  Diagnose a target
  vault     Vault operations
  help      Print this message

Options:
  -h, --help
          Print help
  -V, --version
          Print version
"""
CHECK_HELP = """\
Usage: dcert check [OPTIONS] [TARGETS]...

Options:
  -f, --format <FORMAT>  Output format
      --client-cert <PATH>  Client certificate
      --client-key <PATH>   Client key
      --expiry-warn <DAYS>  Warn days
  -h, --help             Print help
"""
DIAGNOSE_HELP = """\
Usage: dcert diagnose [OPTIONS] <TARGETS>...

Options:
      --client-cert <PATH>
      --client-key <PATH>
  -h, --help
"""
VAULT_HELP = """\
Usage: dcert vault [OPTIONS] <COMMAND>

Commands:
  issue  Issue a certificate
  help   Print this message

Options:
      --debug             Debug output
      --auth-method <M>   Auth method
  -h, --help
"""
ISSUE_HELP = """\
Usage: dcert vault issue [OPTIONS] --cn <CN>

Options:
      --cn <CN>
      --role <ROLE>
  -h, --help
"""


def tree() -> object:
    def node(path: tuple[str, ...], text: str) -> object:
        flags, valued, children, needs = cdc.parse_help(text)
        return cdc.Command(path=path, flags=flags, valued=valued, needs_subcommand=needs)

    top = node((), TOP_HELP)
    top.children["check"] = node(("check",), CHECK_HELP)
    top.children["diagnose"] = node(("diagnose",), DIAGNOSE_HELP)
    vault = node(("vault",), VAULT_HELP)
    vault.children["issue"] = node(("vault", "issue"), ISSUE_HELP)
    top.children["vault"] = vault
    return top


GLOBAL = {"-h", "--help", "-V", "--version"}


def check(line: str) -> list[str]:
    snippet = cdc.Snippet("doc", 1, line)
    problems: list[str] = []
    for _program, args in cdc.commands_in(snippet, ["dcert"]):
        problems += cdc.check_invocation(tree(), args, "check", GLOBAL)
    return problems


def test_parse_help_reads_flags_values_and_commands() -> None:
    flags, valued, children, needs = cdc.parse_help(CHECK_HELP)
    assert {"-f", "--format", "--client-key", "--expiry-warn"} <= flags
    assert "--format" in valued
    assert "-f" in valued
    assert children == []
    assert needs is False
    _, _, children, needs = cdc.parse_help(VAULT_HELP)
    assert children == ["issue"]
    assert needs is True


def test_f6_regression_key_instead_of_client_key_fails() -> None:
    problems = check("dcert diagnose https://api.example.com --client-cert c.pem --key c.key")
    assert problems == ["unknown flag --key for <program> diagnose"]
    assert check("dcert diagnose https://x --client-cert c.pem --client-key c.key") == []


def test_default_subcommand_and_parent_flags() -> None:
    assert check("dcert example.com --format json --expiry-warn 30") == []
    assert check("dcert vault --debug --auth-method ldap issue --cn x --role r") == []
    assert check("dcert vault --role r issue --cn x") == ["unknown flag --role for <program> vault"]


def test_unknown_subcommand_and_placeholders() -> None:
    assert check("dcert vault renews --cn x") == ["unknown subcommand 'vault renews'"]
    assert check("dcert vault [GLOBAL OPTIONS] <SUBCOMMAND> [OPTIONS]") == []
    assert check("dcert --version") == []


def test_command_extraction() -> None:
    snippet = cdc.Snippet("doc", 1, "cat cert.pem | dcert --format json && uvx dcert@4.0.7 x.com")
    assert list(cdc.commands_in(snippet, ["dcert"])) == [
        ("dcert", ["--format", "json"]),
        ("dcert", ["x.com"]),
    ]
    env = cdc.Snippet("doc", 1, "DCERT_PROXY=http://p:3128 ./target/release/dcert x.com # note")
    assert list(cdc.commands_in(env, ["dcert"])) == [("dcert", ["x.com"])]


def test_snippets_skip_json_and_join_continuations() -> None:
    text = "\n".join(
        [
            "Run `dcert --version` first.",
            "```json",
            '{"command": "dcert --nope"}',
            "```",
            "```bash",
            "dcert vault \\",
            "  issue --cn x",
            "```",
        ]
    )
    found = [s.text for s in cdc.snippets("doc", text, ["", "bash"])]
    assert found == ["dcert --version", "dcert vault  issue --cn x"]


def test_undocumented_flag_fails() -> None:
    trees = {"dcert": tree()}
    config = {
        "programs": {"dcert": {"default_subcommand": "check"}},
        "shell_languages": ["bash"],
        "global_flags": sorted(GLOBAL),
        "undocumented_ok": {},
    }
    docs = {"README.md": "Use --format, --client-cert, --client-key, --debug, --auth-method, --cn."}
    problems = cdc.check_commands(trees, docs, config)
    assert "dcert check: flag --expiry-warn is in --help but in no document" in problems
    assert "dcert vault issue: flag --role is in --help but in no document" in problems
    assert "dcert check: flag -f is in --help but in no document" in problems


def test_tool_table_against_server() -> None:
    text = "### Tools\n\n| Tool | Description |\n|--|--|\n| `a_tool` | x |\n| `old` | y |\n\nnext"
    documented = cdc.tool_table(text, "### Tools")
    assert documented == ["a_tool", "old"]
    assert cdc.check_tools(documented, ["a_tool", "new_tool"]) == [
        "tool table lists old, which the server does not have",
        "tool table is missing new_tool",
    ]


def test_release_notes_template_is_read_from_the_workflow() -> None:
    config = cdc.load(cdc.CONFIG)
    text = cdc.release_notes(config, cdc.ROOT)
    assert "```bash" in text
    assert "pip install dcert" in text


def test_env_table_matches_in_both_directions() -> None:
    text = "\n".join(
        [
            "<!-- env-table: generated -->",
            "| Group | Variables |",
            "|-------|-----------|",
            "| Proxy | `HTTP_PROXY`, `NO_PROXY` |",
            "| dcert | `DCERT_MCP_*`, `STALE` |",
            "<!-- /env-table -->",
        ]
    )
    documented = cdc.env_table(text)
    assert documented == ["HTTP_PROXY", "NO_PROXY", "DCERT_MCP_*", "STALE"]
    assert cdc.check_env_table(documented, ["HTTP_PROXY", "NO_PROXY", "DCERT_MCP_*", "NEW"]) == [
        "STALE is in the README table but not forwarded by config.yaml",
        "NEW is forwarded by config.yaml but missing from the README table",
    ]


def test_env_table_of_the_repository_is_current() -> None:
    readme = cdc.ROOT / "python" / "dcert-mcp" / "README.md"
    config = cdc.ROOT / "python" / "dcert-mcp" / "src" / "dcert_mcp" / "config.yaml"
    forwarded = cdc.load(config)["subprocess"]["passthrough_env"]
    assert cdc.check_env_table(cdc.env_table(readme.read_text(encoding="utf-8")), forwarded) == []
