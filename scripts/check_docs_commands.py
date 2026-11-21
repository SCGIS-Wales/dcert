#!/usr/bin/env python3
"""Check that the documentation matches the built binaries.

The README once documented ``dcert diagnose ... --key``, a flag that does not
exist, and nothing noticed. This script reads ``--help`` of the built
``dcert`` and ``dcert-mcp`` recursively and compares it with every command
line in the documents listed in ``scripts/docs_commands.yaml`` (fenced shell
blocks and inline code) and in the release notes template:

* a documented subcommand or flag the binary does not have fails;
* a flag the binary has that no document mentions fails, unless it is listed
  under ``undocumented_ok`` with a reason;
* the MCP tool table in the README must list exactly the tools the server
  returns from ``tools/list``.

Usage::

    python scripts/check_docs_commands.py commands --bin-dir target/release

"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import click
import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "scripts" / "docs_commands.yaml"
FLAG = re.compile(r"(?<![\w-])(--[a-z0-9][a-z0-9-]*|-[a-zA-Z])(?![\w-])")
OPTION_LINE = re.compile(r"^\s{2,}(-[a-zA-Z], )?(--[a-z0-9][a-z0-9-]*|-[a-zA-Z])\b( [<\[])?")
FENCE = re.compile(r"^(\s*)(```|~~~)\s*([\w+-]*)")
INLINE = re.compile(r"`([^`\n]+)`")
SEPARATORS = frozenset({"|", "||", "&&", ";", "&"})
TABLE_TOOL = re.compile(r"^\|\s*`([a-z0-9_]+)`\s*\|")
HANDSHAKE = [
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "check-docs", "version": "0"},
        },
    },
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
]


# ---------------------------------------------------------------------------
# Help tree
# ---------------------------------------------------------------------------


@dataclass
class Command:
    """One command or subcommand: its flags and children."""

    path: tuple[str, ...]
    flags: set[str] = field(default_factory=set)
    #: Flags that take a value (``--format <FORMAT>``).
    valued: set[str] = field(default_factory=set)
    children: dict[str, Command] = field(default_factory=dict)
    needs_subcommand: bool = False


def parse_help(text: str) -> tuple[set[str], set[str], list[str], bool]:
    """``(flags, valued flags, subcommands, needs_subcommand)`` from one ``--help`` text."""
    flags: set[str] = set()
    valued: set[str] = set()
    subcommands: list[str] = []
    needs = False
    section = ""
    for line in text.splitlines():
        if line.startswith("Usage:"):
            needs = "<COMMAND>" in line and "[COMMAND]" not in line
        if line and not line[0].isspace():
            section = line.rstrip(":").strip().lower()
            continue
        if section == "commands":
            match = re.match(r"^\s{2}([a-z0-9][a-z0-9-]*)\s", line + " ")
            if match and match[1] != "help":
                subcommands.append(match[1])
        elif section in ("options", "arguments") or section.endswith("options"):
            match = OPTION_LINE.match(line)
            if match:
                names = [match[2]] + ([match[1].rstrip(", ")] if match[1] else [])
                flags.update(names)
                if match[3]:
                    valued.update(names)
    return flags, valued, subcommands, needs


def help_text(binary: Path, path: Sequence[str]) -> str:
    result = subprocess.run(  # noqa: S603 - the built binary, fixed arguments
        [str(binary), *path, "--help"], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise click.ClickException(f"{binary} {' '.join(path)} --help failed: {result.stderr}")
    return result.stdout


def build_tree(binary: Path, path: tuple[str, ...] = ()) -> Command:
    flags, valued, subcommands, needs = parse_help(help_text(binary, path))
    node = Command(path=path, flags=flags, valued=valued, needs_subcommand=needs)
    for name in subcommands:
        node.children[name] = build_tree(binary, (*path, name))
    return node


def walk(node: Command) -> Iterator[Command]:
    yield node
    for child in node.children.values():
        yield from walk(child)


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Snippet:
    """A command line found in a document."""

    source: str
    line: int
    text: str


def release_notes(config: Mapping[str, Any], root: Path) -> str:
    """The release notes template from the workflow, unescaped to Markdown."""
    spec = config["release_notes"]
    lines = (root / spec["workflow"]).read_text(encoding="utf-8").splitlines()
    start = next(i for i, text in enumerate(lines) if text.strip() == spec["start"])
    end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == spec["end"])
    body = [text.strip() for text in lines[start + 1 : end]]
    return "\n".join(body).replace("\\`", "`").replace("\\$", "$")


def snippets(name: str, text: str, languages: Iterable[str]) -> Iterator[Snippet]:
    """Command lines from fenced shell blocks and from inline code outside fences."""
    shells = set(languages)
    fence: str | None = None
    language = ""
    pending: list[str] = []
    pending_line = 0
    for number, line in enumerate(text.splitlines(), start=1):
        match = FENCE.match(line)
        if match:
            if fence is None:
                fence, language = match[2], match[3].lower()
            elif match[2] == fence:
                fence = None
            continue
        if fence is not None:
            if language not in shells:
                continue
            stripped = line.strip()
            if not pending:
                pending_line = number
            if stripped.endswith("\\"):
                pending.append(stripped[:-1])
                continue
            pending.append(stripped)
            yield Snippet(name, pending_line, " ".join(pending))
            pending = []
            continue
        for inline in INLINE.findall(line):
            yield Snippet(name, number, inline)


def commands_in(snippet: Snippet, programs: Iterable[str]) -> Iterator[tuple[str, list[str]]]:
    """``(program, arguments)`` for each invocation of a checked program in a snippet."""
    text = snippet.text.strip()
    if text.startswith(("$ ", "> ")):
        text = text[2:]
    try:
        tokens = shlex.split(text, comments=True, posix=True)
    except ValueError:
        tokens = text.split()
    wanted = set(programs)
    segment: list[str] = []
    for token in [*tokens, ";"]:
        if token in SEPARATORS or token.endswith(";"):
            if token.endswith(";") and token not in SEPARATORS:
                segment.append(token[:-1])
            yield from _invocation(segment, wanted)
            segment = []
        else:
            segment.append(token)


def _invocation(segment: list[str], wanted: set[str]) -> Iterator[tuple[str, list[str]]]:
    words = list(segment)
    while words and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]):
        words.pop(0)  # VAR=value prefixes
    if words and words[0] in ("uvx", "timeout", "sudo", "exec", "time"):
        words.pop(0)
        while words and (words[0].startswith("-") or words[0].isdigit()):
            words.pop(0)
    if not words:
        return
    program = Path(words[0].split("@", 1)[0]).name.removesuffix(".exe")
    if program in wanted:
        yield program, words[1:]


def check_invocation(
    tree: Command, arguments: Sequence[str], default: str | None, global_flags: set[str]
) -> list[str]:
    """Problems with one documented invocation: unknown subcommands and flags.

    Arguments are read left to right, as clap does: a flag belongs to the
    command reached so far (``dcert vault --debug issue --cn x``), a word that
    names a child descends into it, and the first positional of ``dcert``
    selects the default subcommand.
    """
    node = tree
    problems: list[str] = []
    words = list(arguments)
    i = 0
    while i < len(words):
        word = words[i]
        i += 1
        if (
            word in ("-", "--", "...", "…")
            or word.startswith(("<", "[", "$"))
            or word.endswith(("]", ">"))
        ):
            continue
        if word.startswith("-") and not re.match(r"^-\d", word):
            flag = word.split("=", 1)[0]
            if not FLAG.fullmatch(flag):
                continue
            scope = [node]
            if node is tree and default in node.children:
                scope.append(node.children[default])
            if not any(flag in n.flags for n in scope) and flag not in global_flags:
                shown = " ".join(("<program>", *node.path))
                problems.append(f"unknown flag {flag} for {shown}")
                nxt = words[i] if i < len(words) else ""
                if "=" not in word and nxt and not nxt.startswith("-") and nxt not in node.children:
                    i += 1  # most likely the unknown flag's value
            elif "=" not in word and any(flag in n.valued for n in scope):
                i += 1  # the flag's value
            continue
        if word in node.children:
            node = node.children[word]
            continue
        if node.children:
            if node is tree and default in node.children:
                node = node.children[default]
            elif node.needs_subcommand and word != "help":
                problems.append(f"unknown subcommand {' '.join((*node.path, word))!r}")
                break
    return problems


def mentioned_flags(texts: Iterable[str]) -> set[str]:
    found: set[str] = set()
    for text in texts:
        found.update(FLAG.findall(text))
    return found


def tool_table(text: str, heading: str) -> list[str]:
    """Tool names in the first table after ``heading``."""
    lines = text.splitlines()
    start = lines.index(heading)
    names: list[str] = []
    in_table = False
    for line in lines[start + 1 :]:
        if line.startswith("|"):
            in_table = True
            match = TABLE_TOOL.match(line)
            if match:
                names.append(match[1])
        elif in_table:
            break
    return names


def server_tools(binary: Path) -> list[str]:
    payload = "".join(json.dumps(m) + "\n" for m in HANDSHAKE)
    with subprocess.Popen(  # noqa: S603 - the built server, fixed arguments
        [str(binary)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    ) as proc:
        if proc.stdin is None or proc.stdout is None:
            raise click.ClickException("could not open the server's stdio")
        proc.stdin.write(payload)
        proc.stdin.flush()
        tools: list[str] | None = None
        for line in proc.stdout:
            message = json.loads(line)
            if message.get("id") == 2:
                tools = [t["name"] for t in message["result"]["tools"]]
                break
        proc.kill()
    if tools is None:
        raise click.ClickException(f"{binary} did not answer tools/list")
    return tools


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def documents(config: Mapping[str, Any], root: Path) -> dict[str, str]:
    docs = {name: (root / name).read_text(encoding="utf-8") for name in config["documents"]}
    docs["release notes template"] = release_notes(config, root)
    return docs


def check_commands(
    trees: Mapping[str, Command], docs: Mapping[str, str], config: Mapping[str, Any]
) -> list[str]:
    problems: list[str] = []
    global_flags = set(config.get("global_flags") or [])
    programs = config["programs"]
    for name, text in docs.items():
        for snippet in snippets(name, text, config["shell_languages"]):
            for program, arguments in commands_in(snippet, trees):
                default = (programs.get(program) or {}).get("default_subcommand")
                for problem in check_invocation(trees[program], arguments, default, global_flags):
                    problems.append(f"{snippet.source}:{snippet.line}: {problem}: {snippet.text}")
    mentioned = mentioned_flags(docs.values()) | global_flags
    allowed = config.get("undocumented_ok") or {}
    for program, tree in trees.items():
        for node in walk(tree):
            for flag in sorted(node.flags - mentioned):
                label = " ".join((program, *node.path))
                if flag not in allowed.get(label, {}):
                    problems.append(f"{label}: flag {flag} is in --help but in no document")
    return problems


def check_tools(documented: Sequence[str], served: Sequence[str]) -> list[str]:
    problems = [
        f"tool table lists {t}, which the server does not have"
        for t in sorted(set(documented) - set(served))
    ]
    problems += [f"tool table is missing {t}" for t in sorted(set(served) - set(documented))]
    return problems


def load(config_path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise click.ClickException(f"{config_path}: not a mapping")
    return loaded


@click.group()
def main() -> None:
    """Check the documentation against the binaries and config.yaml."""


@main.command()
@click.option(
    "--bin-dir",
    type=click.Path(path_type=Path, file_okay=False),
    required=True,
    help="Directory with the built dcert and dcert-mcp.",
)
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=CONFIG)
def commands(bin_dir: Path, config_path: Path) -> None:
    """Documented subcommands, flags and MCP tools against --help and tools/list."""
    config = load(config_path)
    suffix = ".exe" if sys.platform == "win32" else ""
    trees = {p: build_tree(bin_dir / f"{p}{suffix}") for p in config["programs"]}
    docs = documents(config, ROOT)
    problems = check_commands(trees, docs, config)
    table = config["tool_table"]
    documented = tool_table(docs[table["document"]], table["heading"])
    served = server_tools(bin_dir / f"dcert-mcp{suffix}")
    problems += check_tools(documented, served)
    for problem in problems:
        click.echo(f"::error::{problem}", err=True)
    if problems:
        sys.exit(1)
    flags = sum(len(n.flags) for t in trees.values() for n in walk(t))
    click.echo(f"documentation matches: {flags} flags, {len(served)} MCP tools")


ENV_TABLE_START = "<!-- env-table"
ENV_TABLE_END = "<!-- /env-table -->"
ENV_NAME = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*\*?)`")


def env_table(text: str) -> list[str]:
    """Variable names in the README table between the ``env-table`` markers."""
    start = text.find(ENV_TABLE_START)
    end = text.find(ENV_TABLE_END)
    if start < 0 or end < start:
        raise click.ClickException("the env-table markers are missing")
    names: list[str] = []
    for line in text[start:end].splitlines():
        if line.startswith("|") and not line.startswith("|-"):
            cells = line.strip("|").split("|")
            if len(cells) >= 2:
                names.extend(ENV_NAME.findall(cells[1]))
    return names


def check_env_table(documented: Sequence[str], forwarded: Sequence[str]) -> list[str]:
    """Both directions of drift between the README table and ``passthrough_env``."""
    problems = [
        f"{n} is in the README table but not forwarded by config.yaml"
        for n in sorted(set(documented) - set(forwarded))
    ]
    problems += [
        f"{n} is forwarded by config.yaml but missing from the README table"
        for n in sorted(set(forwarded) - set(documented))
    ]
    problems += [
        f"{n} is listed twice in the README table"
        for n in sorted({n for n in documented if documented.count(n) > 1})
    ]
    return problems


@main.command("env-table")
@click.option(
    "--readme",
    type=click.Path(path_type=Path, dir_okay=False),
    default=ROOT / "python" / "dcert-mcp" / "README.md",
    show_default=True,
)
@click.option(
    "--config-yaml",
    type=click.Path(path_type=Path, dir_okay=False),
    default=ROOT / "python" / "dcert-mcp" / "src" / "dcert_mcp" / "config.yaml",
    show_default=True,
)
def env_table_command(readme: Path, config_yaml: Path) -> None:
    """The forwarded environment table in the dcert-mcp README against config.yaml."""
    documented = env_table(readme.read_text(encoding="utf-8"))
    forwarded = [str(n) for n in load(config_yaml)["subprocess"]["passthrough_env"]]
    problems = check_env_table(documented, forwarded)
    for problem in problems:
        click.echo(f"::error::{problem}", err=True)
    if problems:
        sys.exit(1)
    click.echo(f"environment table matches config.yaml: {len(forwarded)} variables")


if __name__ == "__main__":
    main()
