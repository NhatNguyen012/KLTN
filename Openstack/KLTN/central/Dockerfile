# Central services image (api, archiver, normalizer, framework). Build context: Openstack/KLTN.
FROM python:3.12-slim-bookworm
WORKDIR /app
COPY central/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY serving/kltn_features/ ./kltn_features/
COPY central/app/ .
USER 1000:1000
CMD ["uvicorn", "api:app", "--host", "127.0.0.1", "--port", "18080", "--no-access-log"]
