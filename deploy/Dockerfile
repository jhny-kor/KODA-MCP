FROM python@sha256:72d3d75f2639ab82b34b29390ad3d6e0827c775befee94edda8e9976818f488d

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app
COPY requirements-linux-amd64-py312.lock /app/requirements-linux-amd64-py312.lock
COPY wheelhouse/ /wheelhouse/
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheelhouse --require-hashes -r /app/requirements-linux-amd64-py312.lock \
    && python -m pip check \
    && rm -rf /wheelhouse /root/.cache

COPY pyproject.toml LICENSE NOTICE /app/
COPY src/ /app/src/
RUN groupadd --gid 10001 koda \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin koda \
    && python -m compileall -q /app/src

USER 10001:10001
EXPOSE 8766
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8766/healthz', timeout=2).read()"
ENTRYPOINT ["python", "-m", "uvicorn", "koda_mcp.server:app", "--host", "0.0.0.0", "--port", "8766", "--workers", "1", "--no-access-log"]
