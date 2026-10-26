# --- frontend build ---
FROM node:20-alpine AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# --- runtime ---
FROM python:3.12-slim
# Proxy headers (real client IP) are trusted only from FORWARDED_ALLOW_IPS; install.sh sets it when Caddy is used
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data STATIC_DIR=/app/static FORWARDED_ALLOW_IPS=127.0.0.1
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY VERSION ./VERSION
COPY --from=frontend /build/dist ./static
# Which git tree the image was built from: lets the admin tell whether an update is available
ARG APP_TREE="" APP_COMMIT="" APP_COMMIT_DATE="" APP_BUILT_AT=""
ENV APP_TREE=$APP_TREE APP_COMMIT=$APP_COMMIT APP_COMMIT_DATE=$APP_COMMIT_DATE APP_BUILT_AT=$APP_BUILT_AT
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
