FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --system --home-dir /data patchmonitor \
    && mkdir -p /data && chown patchmonitor /data
COPY app ./app
ENV DATA_DIR=/data
USER patchmonitor
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
