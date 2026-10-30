FROM python:3.12-slim-bookworm
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir torch==2.7.1+cpu --index-url https://download.pytorch.org/whl/cpu
COPY worker.py .
USER 1000:1000
ENV OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 PYTHONDONTWRITEBYTECODE=1
CMD ["python", "-u", "worker.py"]
