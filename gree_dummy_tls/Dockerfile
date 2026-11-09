FROM python:3.13-alpine

RUN apk add --no-cache jq

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gree-dummy-tls-server.py run.sh ./
RUN chmod +x gree-dummy-tls-server.py run.sh \
    && ln -s /data/keys /keys

CMD ["/app/run.sh"]
