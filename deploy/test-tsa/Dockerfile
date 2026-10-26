FROM alpine:3.20
RUN apk add --no-cache python3 openssl
COPY server.py /server.py
CMD ["python3", "/server.py"]
