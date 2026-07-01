FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    nmap \
    libnotify-bin \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python3", "dashboard/app.py"]
