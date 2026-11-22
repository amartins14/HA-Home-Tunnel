FROM python:3.13-alpine
RUN apk add --no-cache su-exec
RUN pip install --no-cache-dir aiohttp==3.14.4 \
    && addgroup -g 10001 tunnel && adduser -D -u 10001 -G tunnel tunnel
WORKDIR /app
COPY connector/connector.py connector/policy.py connector/metrics.py connector/audit.py connector/service.py connector/setup.html /app/
COPY config.yaml /app/app-config.yaml
COPY start.sh /app/start.sh
RUN chmod 0755 /app/start.sh
ENV PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["/app/start.sh"]
CMD ["python", "-u", "/app/service.py"]
