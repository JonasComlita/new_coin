FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN apt-get update && apt-get install -y \
    libssl-dev \
    libpq-dev \
    gcc \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY originalcoin.py .

EXPOSE 8443 8000

ENV ORIGINALCOIN_USE_ACME=false \
    ORIGINALCOIN_NETWORK_PORT=8443 \
    ORIGINALCOIN_DOMAIN=localhost

CMD ["python", "originalcoin.py", "--host", "0.0.0.0"]