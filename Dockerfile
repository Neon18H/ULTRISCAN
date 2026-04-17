FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        ffuf \
        gcc \
        git \
        golang-go \
        gobuster \
        libnet-ssleay-perl \
        libwhisker2-perl \
        libcurl4-openssl-dev \
        make \
        nmap \
        netcat-openbsd \
        perl \
        ruby-full \
        ruby-dev \
        sqlmap \
        unzip \
        whatweb \
        zlib1g-dev \
    && export GOBIN=/usr/local/bin \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/hahwul/dalfox/v2@latest \
    && NUCLEI_VERSION=3.3.9 \
    && curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /tmp \
    && install -m 0755 /tmp/nuclei /usr/local/bin/nuclei \
    && if apt-cache show nikto >/dev/null 2>&1; then \
        apt-get install -y --no-install-recommends nikto; \
      else \
        git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
        && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto; \
      fi \
    && git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/seclists \
    && nuclei -update-templates \
    && rm -f /tmp/nuclei.zip /tmp/nuclei \
    && if ! gem install --no-document wpscan; then \
        echo "WARNING: WPScan installation failed; continuing build without wpscan binary." > /usr/local/share/wpscan-install-warning.txt; \
      fi \
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
