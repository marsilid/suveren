FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    SUVEREN_CACHE=/cache

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

# Reports are written to /work/reports; mount a folder there to keep them.
WORKDIR /work
VOLUME ["/work", "/cache"]
ENTRYPOINT ["suveren"]
CMD ["--help"]
