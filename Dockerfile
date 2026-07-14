# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM python:3.14.6-slim-bookworm@sha256:4ff4b92a68355dbdb52584ab3391dff8d371a61d4e063468bfd0130e3189c6d9

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.lock ./
RUN python -m pip install --requirement requirements.lock \
    && groupadd --system --gid 10001 denilicense \
    && useradd --system --uid 10001 --gid denilicense \
        --home-dir /var/lib/denilicense --create-home denilicense \
    && mkdir -p /var/lib/denilicense/secrets \
    && chown -R denilicense:denilicense /var/lib/denilicense

COPY --chown=denilicense:denilicense src/ ./src/
COPY --chown=denilicense:denilicense docs/ENTITLEMENTS.md ./docs/ENTITLEMENTS.md

USER 10001:10001
WORKDIR /var/lib/denilicense
EXPOSE 8080
ENTRYPOINT ["python", "-m", "denilicense"]
CMD ["serve"]
