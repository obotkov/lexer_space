# --- frontend build ---
FROM node:20-alpine AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# --- runtime ---
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data STATIC_DIR=/app/static
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
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["python", "-m", "app.healthcheck"]
# Binds BIND_ADDR:PORT on the host network, over HTTPS when a certificate is enabled (app/run.py)
CMD ["python", "-m", "app.run"]
