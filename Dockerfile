FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap arp-scan iproute2 iputils-ping dnsutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY VERSION ./VERSION
ARG APP_VERSION=""
ENV APP_VERSION=${APP_VERSION}
ENV NMAP_PRIVILEGED=1 PYTHONUNBUFFERED=1 DATABASE_URL=sqlite:////data/scanner.db DATA_DIR=/data
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD python -c "import urllib.request,os,ssl;from app import tls;s=tls.enabled();urllib.request.urlopen(('https' if s else 'http')+'://127.0.0.1:%s/api/health'%os.environ.get('PORT','8080'),timeout=4,context=ssl._create_unverified_context() if s else None)"
CMD ["python","-m","app.serve"]
