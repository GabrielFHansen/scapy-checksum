FROM python:3.11-slim

# Instala dependências básicas
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    iproute2 \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Instala o Scapy
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o código
COPY app/ /app
WORKDIR /app

# Executa o script
CMD ["python", "main.py"]
