FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN apt-get update && apt-get install -y \
    curl \
    iputils-ping \
    libmagic1 \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

COPY connectors/otx/requirements.txt /app/
RUN python -m pip uninstall --yes setuptools msgpack || true
RUN pip install --no-cache-dir -r requirements.txt

COPY connectors/otx/*.py /app/
COPY connectors /app/connectors
COPY core /app/core
COPY exporters /app/exporters
COPY gateway /app/gateway

CMD ["python", "connector.py"]
