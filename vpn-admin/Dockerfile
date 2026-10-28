# --- frontend build ---
FROM node:20-alpine AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# --- Xray-core: the admin checks every connection through it, the way a client would ---
FROM python:3.12-slim AS xray
ARG XRAY_VERSION=v26.10.21
# one line, not a heredoc: install.sh may build with the classic builder, which does not know them
RUN python -c "import io, os, platform, urllib.request, zipfile; \
asset = {'x86_64': 'Xray-linux-64.zip', 'aarch64': 'Xray-linux-arm64-v8a.zip'}[platform.machine()]; \
url = 'https://github.com/XTLS/Xray-core/releases/download/' + os.environ['XRAY_VERSION'] + '/' + asset; \
zipfile.ZipFile(io.BytesIO(urllib.request.urlopen(url, timeout=120).read())).extract('xray', '/out'); \
os.chmod('/out/xray', 0o755)"

# --- runtime ---
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data STATIC_DIR=/app/static
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY VERSION ./VERSION
COPY --from=frontend /build/dist ./static
COPY --from=xray /out/xray /usr/local/bin/xray
# Which git tree the image was built from: lets the admin tell whether an update is available
ARG APP_TREE="" APP_COMMIT="" APP_COMMIT_DATE="" APP_BUILT_AT=""
ENV APP_TREE=$APP_TREE APP_COMMIT=$APP_COMMIT APP_COMMIT_DATE=$APP_COMMIT_DATE APP_BUILT_AT=$APP_BUILT_AT
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["python", "-m", "app.healthcheck"]
# Binds BIND_ADDR:PORT on the host network, over HTTPS when a certificate is enabled (app/run.py)
CMD ["python", "-m", "app.run"]
