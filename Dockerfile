FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Build context is the parent directory (/home/manish/Desktop/machine)
# so sibling repos are accessible during the build.

# Install IAM client SDK from source, then discard the source tree.
# Re-added: removed as dead weight in a88f6ac when nothing imported it;
# app/services/iam_client.py now uses it for RS256/JWKS/HS256 token
# verification (IAM Foundation gateway integration).
COPY omnibioai-iam-client /tmp/omnibioai-iam-client
RUN pip install --no-cache-dir /tmp/omnibioai-iam-client \
 && rm -rf /tmp/omnibioai-iam-client

# Install gateway Python dependencies.
COPY omnibioai-api-gateway/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the gateway service source.
COPY omnibioai-api-gateway .

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
