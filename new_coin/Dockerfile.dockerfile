FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

ENV PEER_AUTH_SECRET="your_secure_secret_here"
ENV SSL_CERT_PATH="/app/server.crt"
ENV SSL_KEY_PATH="/app/server.key"

CMD ["python", "main.py"]