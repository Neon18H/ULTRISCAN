FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x /app/start.sh /app/worker.sh \
    && if [ -f /app/entrypoint.sh ]; then chmod +x /app/entrypoint.sh; fi

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["/app/start.sh"]
