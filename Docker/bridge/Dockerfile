FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY bridge/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY scripts/kltn_model_bridge.py /app/kltn_model_bridge.py

CMD ["python3", "/app/kltn_model_bridge.py"]
