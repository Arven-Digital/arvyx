FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93

ARG ARVYX_RELEASE_BUILD_ID=local
LABEL org.opencontainers.image.revision=$ARVYX_RELEASE_BUILD_ID

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TMPDIR=/tmp \
    SQLITE_TMPDIR=/tmp

WORKDIR /app

COPY pyproject.toml README.md LICENSE NOTICE ./
COPY requirements/build.lock ./requirements/build.lock
COPY packages ./packages
COPY apps/control-center-api/src ./apps/control-center-api/src
COPY fixtures ./fixtures

# Install both console scripts instead of depending on a source-checkout
# PYTHONPATH. Shipped code stays root-owned and read-only at runtime.
RUN python -m pip install --no-cache-dir --require-hashes -r requirements/build.lock \
    && python -m pip install --no-cache-dir --no-build-isolation --no-deps . \
    && useradd --create-home --uid 10001 arvyx \
    && install -d -o arvyx -g arvyx -m 0750 /data \
    && chmod -R a+rX /app

USER arvyx
VOLUME ["/data"]
EXPOSE 8765

HEALTHCHECK --interval=5s --timeout=5s --start-period=45s --retries=18 \
  CMD ["python", "-m", "arvyx_control.container_readiness"]

# The image's safe no-configuration default remains the synthetic demo. The
# Compose server service overrides this command with an authenticated API.
CMD ["arvyx", "demo", "--vault", "fixtures/synthetic-vault", "--json"]
