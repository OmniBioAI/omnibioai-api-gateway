# syntax=docker/dockerfile:1
FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential curl git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# GHCR release follow-up: build context is now this repo alone (`.`), not
# the parent directory -- the previous COPY omnibioai-iam-client /tmp/...
# step required a sibling checkout, which no GitHub Actions workflow in
# this org has ever been able to do for a *private* sibling repo. Adopts
# the same pattern already proven in production by omnibioai-tes and
# omnibioai-rag instead: pyproject.toml declares omnibioai-iam-client as a
# pinned git+https dependency (private repo -- GitHub Packages has no
# PyPI-format registry), and `pip install .` re-resolves ALL declared
# deps including direct-URL ones (it does not trust a same-named package
# already being installed the way it does for plain version-range
# requirements), so the token must be available for pip's own git clone
# here, not just a separate pre-install step.
COPY pyproject.toml .
COPY app/ ./app/

# Uses a BuildKit secret mount (not ARG/ENV -- ARG/ENV values get echoed
# into BuildKit's progress output for the RUN instruction that uses them,
# leaking the token into build logs) and an ephemeral GIT_ASKPASS helper
# rather than a `git config --global url.insteadOf` credential rewrite:
# when the mounted credential is rejected, git's own "could not read
# Password for 'https://<credential>@github.com'" error prints the
# fully-expanded credentialed URL to stderr, which BuildKit captures into
# the build log. GIT_ASKPASS avoids that because git never constructs a
# credentialed URL at all -- it calls the helper out-of-band for the
# password. The helper reads the mounted secret only when git asks for one
# and is removed by an EXIT trap in the same layer. hatchling is
# pre-installed explicitly (unlike omnibioai-tes/omnibioai-rag, both
# setuptools-backed) because this repo's own [build-system] uses
# hatchling.build -- confirmed necessary by an actual local build; see
# pyproject.toml's [tool.hatch.metadata] for the one other
# hatchling-specific allowance the pinned dependency below needs.
RUN --mount=type=secret,id=github_token \
    set -eu; \
    printf '%s\n' \
      '#!/bin/sh' \
      'case "$1" in' \
      '  *Username*) printf "%s\n" "x-access-token" ;;' \
      '  *Password*) cat /run/secrets/github_token ;;' \
      '  *) exit 1 ;;' \
      'esac' > /tmp/git-askpass; \
    chmod 700 /tmp/git-askpass; \
    trap 'rm -f /tmp/git-askpass' EXIT; \
    pip install --no-cache-dir hatchling; \
    GIT_ASKPASS=/tmp/git-askpass GIT_TERMINAL_PROMPT=0 \
      pip install --no-cache-dir --upgrade-strategy only-if-needed .

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
