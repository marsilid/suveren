FROM python:3.12-slim

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

# Reports are written to /work/reports; mount a folder there to keep them.
WORKDIR /work
VOLUME ["/work", "/cache"]
ENTRYPOINT ["suveren"]
CMD ["--help"]
