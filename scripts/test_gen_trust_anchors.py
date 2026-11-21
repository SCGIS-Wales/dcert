"""Tests for scripts/gen_trust_anchors.py (no network)."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import yaml

_PATH = Path(__file__).with_name("gen_trust_anchors.py")
_SPEC = importlib.util.spec_from_file_location("gen_trust_anchors", _PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
gta = importlib.util.module_from_spec(_SPEC)
sys.modules["gen_trust_anchors"] = gta
_SPEC.loader.exec_module(gta)


def octal_block(data: bytes) -> str:
    return "".join(f"\\{b:03o}" for b in data)


def certdata(entries: list[tuple[str, bytes, str, str, bool]]) -> str:
    """A minimal certdata.txt: (label, der, server trust, email trust, email distrust)."""
    out = []
    for label, der, server, email, distrust in entries:
        distrust_line = (
            f"CKA_NSS_EMAIL_DISTRUST_AFTER MULTILINE_OCTAL\n{octal_block(b'250101000000Z')}\nEND"
            if distrust
            else "CKA_NSS_EMAIL_DISTRUST_AFTER CK_BBOOL CK_FALSE"
        )
        sha1 = hashlib.sha1(der).digest()  # noqa: S324 - mirrors NSS
        out.append(
            f'#\n# Certificate "{label}"\n#\nCKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\n'
            f'CKA_LABEL UTF8 "{label}"\nCKA_VALUE MULTILINE_OCTAL\n{octal_block(der)}\nEND\n'
            f"{distrust_line}\n"
        )
        out.append(
            f'# Trust for "{label}"\nCKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST\n'
            f'CKA_LABEL UTF8 "{label}"\n'
            f"CKA_CERT_SHA1_HASH MULTILINE_OCTAL\n{octal_block(sha1)}\nEND\n"
            f"CKA_TRUST_SERVER_AUTH CK_TRUST {server}\n"
            f"CKA_TRUST_EMAIL_PROTECTION CK_TRUST {email}\n"
        )
    return "\n".join(out)


TRUSTED = "CKT_NSS_TRUSTED_DELEGATOR"
NOT = "CKT_NSS_MUST_VERIFY_TRUST"


def test_email_only_selects_email_roots_without_website_trust_or_distrust() -> None:
    text = certdata(
        [
            ("Web and mail", b"\x30\x01", TRUSTED, TRUSTED, False),
            ("Mail only", b"\x30\x02", NOT, TRUSTED, False),
            ("Web only", b"\x30\x03", TRUSTED, NOT, False),
            ("Mail with distrust date", b"\x30\x04", NOT, TRUSTED, True),
        ]
    )
    roots = gta.nss_roots(text)
    assert {r.label for r in roots} == {
        "Web and mail",
        "Mail only",
        "Web only",
        "Mail with distrust date",
    }
    assert [r.label for r in gta.email_only(roots)] == ["Mail only"]
    assert gta.email_only(roots)[0].der == b"\x30\x02"


def test_render_is_stable_pem_with_labels() -> None:
    text = gta.render_email(
        gta.email_only(gta.nss_roots(certdata([("Mail only", b"\x30\x02", NOT, TRUSTED, False)]))),
        "NSS_X",
    )
    assert text.startswith("# Roots Mozilla trusts for email")
    assert "# Mail only\n# SHA-256 " in text
    assert text.count("-----BEGIN CERTIFICATE-----") == 1


def test_x9_files_match_the_published_fingerprints() -> None:
    config = yaml.safe_load(gta.CONFIG.read_text(encoding="utf-8"))
    assert len(config["x9_financial"]["anchors"]) == 11
    assert gta.x9_problems(config) == []


def test_x9_problem_reported_for_a_changed_file(tmp_path: Path) -> None:
    config = yaml.safe_load(gta.CONFIG.read_text(encoding="utf-8"))
    anchor = dict(config["x9_financial"]["anchors"][0], sha256="00" * 32)
    target = tmp_path / anchor["file"]
    target.parent.mkdir(parents=True)
    target.write_bytes((gta.ROOT / anchor["file"]).read_bytes())
    problems = gta.x9_problems({"x9_financial": {"anchors": [anchor]}}, root=tmp_path)
    assert len(problems) == 1
    assert "published" in problems[0]


def test_committed_email_bundle_lists_the_sectigo_roots() -> None:
    bundle = (gta.ROOT / "src" / "trust_anchors" / "mozilla_email.pem").read_text(encoding="utf-8")
    assert "# Sectigo Public Email Protection Root R46" in bundle
    assert "# Sectigo Public Email Protection Root E46" in bundle
    assert "Sectigo Public Server Authentication Root" not in bundle
