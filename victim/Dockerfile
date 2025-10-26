FROM python:3.11-slim

RUN apt-get update && apt-get install -y openssl curl ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY pinned_client.py /workspace/pinned_client.py
RUN chmod +x /workspace/pinned_client.py

CMD ["/bin/bash"]
