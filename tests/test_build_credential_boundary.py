"""Regression checks for the private-dependency build credential boundary.

These checks intentionally inspect structure only.  They never read a build
credential and therefore remain safe to run in ordinary unit-test jobs.
"""

from pathlib import Path
import re


DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile"


def _dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def _executable_lines(text: str) -> str:
    """Drop comment lines so explanatory prose mentioning the old pattern
    (for documentation purposes) doesn't trip the check below."""
    return "\n".join(
        line for line in text.splitlines() if not line.strip().startswith("#")
    )


def test_no_credential_bearing_git_url_construction() -> None:
    text = _executable_lines(_dockerfile())
    assert "git config --global url." not in text
    assert not re.search(
        r"https://[^\s\"']*(?:github_token|/run/secrets|\$\()[^\s\"']*@github\.com",
        text,
        re.IGNORECASE,
    )


def test_secret_is_used_only_via_ephemeral_askpass() -> None:
    text = _dockerfile()
    assert "--mount=type=secret,id=github_token" in text
    assert "GIT_ASKPASS=/tmp/git-askpass" in text
    assert "GIT_TERMINAL_PROMPT=0" in text
    assert "*Password*) cat /run/secrets/github_token" in text
    assert "trap 'rm -f /tmp/git-askpass' EXIT" in text


def test_build_credential_is_not_persisted_as_arg_or_env() -> None:
    text = _dockerfile()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("ARG ", "ENV ")):
            assert "github_token" not in stripped.lower()
            assert "/run/secrets/github_token" not in stripped
