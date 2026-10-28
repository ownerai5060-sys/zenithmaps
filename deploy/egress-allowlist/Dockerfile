FROM python:3.12-slim-bookworm
WORKDIR /app
COPY proxy.py .
ENV EGRESS_LISTEN=0.0.0.0:8888 \
    EGRESS_ALLOWED_HOSTS=
EXPOSE 8888
CMD ["python", "-u", "proxy.py"]
