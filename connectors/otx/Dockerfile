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

RUN for package in python3-msgpack python3-setuptools; do dpkg --purge "$package" || true; done
RUN find /usr/local/lib /usr/lib -type d \( -name 'setuptools-*.dist-info' -o -name 'msgpack-*.dist-info' \) -prune -exec rm -rf {} +

COPY connectors/otx/requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
RUN python -m pip uninstall --yes pip

COPY connectors/otx/*.py /app/
COPY connectors /app/connectors
COPY core /app/core
COPY exporters /app/exporters
COPY gateway /app/gateway

CMD ["python", "connector.py"]
