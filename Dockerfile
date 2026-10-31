# The base image by digest: a retagged image cannot slip in. Dependabot updates it.
FROM python:3.15-slim@sha256:94d3426f1def7db4a106a232ac121bfd975393e5dfd40a619b955fae45fe7913

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    SUVEREN_CACHE=/cache

WORKDIR /app
COPY packaging/requirements.txt ./packaging/
# Dependencies at the versions and hashes of the lock, then Suveren itself.
RUN pip install --no-cache-dir --require-hashes -r packaging/requirements.txt
COPY pyproject.toml README.md LICENSE COPYRIGHT ./
COPY src ./src
RUN pip install --no-cache-dir --no-deps .

# Not root: Chromium's sandbox does not start as root, and --browser refuses to run
# without it. Reports are written to /work/reports; mount a folder there to keep them.
RUN useradd --create-home --uid 10001 suveren \
    && mkdir -p /work /cache && chown suveren:suveren /work /cache
USER suveren
WORKDIR /work
VOLUME ["/work", "/cache"]
ENTRYPOINT ["suveren"]
CMD ["--help"]
