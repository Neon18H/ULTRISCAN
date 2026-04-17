FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        ffuf \
        gobuster \
        nikto \
        nmap \
        netcat-openbsd \
        ruby-full \
        unzip \
        whatweb \
    && NUCLEI_VERSION=3.3.9 \
    && curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /tmp \
    && install -m 0755 /tmp/nuclei /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip /tmp/nuclei \
    && gem install --no-document wpscan \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY worker.sh ./worker.sh
COPY start.sh ./start.sh
COPY entrypoint.sh ./entrypoint.sh
COPY . .

RUN chmod +x /app/start.sh /app/worker.sh /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["/app/start.sh"]
