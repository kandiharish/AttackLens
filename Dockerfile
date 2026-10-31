# AttackLens: one image = API + built SPA + pipeline + synthetic data tools.
#   docker compose up        -> http://localhost:8000
# Layout inside the image mirrors the repo (/app/backend, /app/config, ...) because attacklens.config.REPO_ROOT
# is derived from the package location (editable install).

# ---- stage 1: build the frontend ----------------------------------------------------------------------------
FROM node:22-slim AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
# lockfile was produced on Windows; fall back to `npm install` if platform-specific optional deps are missing
RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- stage 2: runtime -------------------------------------------------------------------------------------------
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ATTACKLENS_OUT=/app/data/out/demo \
    DEMO_SIZE=200M
WORKDIR /app
COPY backend/pyproject.toml backend/pyproject.toml
COPY backend/attacklens backend/attacklens
COPY backend/eval backend/eval
RUN pip install -e backend
COPY config config
COPY tools tools
COPY reports/edr_log_generator.py reports/edr_log_generator.py
COPY --from=web /web/dist frontend/dist
EXPOSE 8000
# First start: generate a small demo set and run the pipeline (with ground truth -> eval_scorecard.json),
# then serve. Later starts reuse data/out/demo from the mounted ./data volume.
CMD ["sh", "-c", "set -e; \
if [ ! -f data/out/demo/incidents_index.json ]; then \
  echo 'attacklens: generating demo data set ('$DEMO_SIZE')'; \
  python tools/gen_dataset.py --size $DEMO_SIZE --out data/raw/demo --workers 2 --force; \
  python -m attacklens.run --raw data/raw/demo --out data/out/demo --ground-truth data/raw/demo/ground_truth/attacks.json; \
fi; \
exec python -m uvicorn attacklens.api:app --host 0.0.0.0 --port 8000"]
