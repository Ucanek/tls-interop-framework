# syntax=docker/dockerfile:1

FROM fedora:39 AS pydeps
RUN dnf install -y --nodocs --setopt=install_weak_deps=False python3-pip \
    && dnf clean all \
    && rm -rf /var/cache/dnf /tmp/sandbox-* /tmp/* /var/tmp/*
RUN mkdir -p /grpc-deps \
    && pip3 install --no-cache-dir --target /grpc-deps \
        'grpcio>=1.80.0,<1.81' \
        'grpcio-tools>=1.80.0,<1.81' \
        'protobuf>=4.21'

FROM fedora:39 AS runtime
RUN dnf install -y --nodocs --setopt=install_weak_deps=False \
        python3 openssl gnutls-utils nss-tools socat coreutils \
    && dnf clean all \
    && rm -rf /var/cache/dnf /tmp/sandbox-* /tmp/* /var/tmp/*

WORKDIR /app
ENV PYTHONPATH=/app:/opt/grpc-deps
ENV PYTHONUNBUFFERED=1
COPY --from=pydeps /grpc-deps /opt/grpc-deps

COPY proto/ ./proto/
COPY src/core ./core
COPY src/wrappers ./wrappers
COPY deploy/wrapper_entry.py ./

RUN mkdir -p /app/certs \
    && openssl req -x509 -newkey rsa:2048 \
        -keyout /app/certs/key_rsa.pem -out /app/certs/cert_rsa.pem -sha256 \
        -days 365 -nodes \
        -subj "/CN=server_node/OU=interop-rsa" \
        -addext "subjectAltName=DNS:server_node" \
    && openssl ecparam -name prime256v1 -genkey -noout -out /app/certs/key_ecdsa.pem \
    && openssl req -new -x509 -key /app/certs/key_ecdsa.pem \
        -out /app/certs/cert_ecdsa.pem -sha256 -days 365 -nodes \
        -subj "/CN=server_node/OU=interop-ecdsa" \
        -addext "subjectAltName=DNS:server_node" \
    && openssl genpkey -algorithm ED25519 -out /app/certs/key_ed25519.pem \
    && openssl req -new -x509 -key /app/certs/key_ed25519.pem \
        -out /app/certs/cert_ed25519.pem -days 365 -nodes \
        -subj "/CN=server_node/OU=interop-ed25519" \
        -addext "subjectAltName=DNS:server_node" \
    && openssl genpkey -algorithm ED448 -out /app/certs/key_ed448.pem \
    && openssl req -new -x509 -key /app/certs/key_ed448.pem \
        -out /app/certs/cert_ed448.pem -days 365 -nodes \
        -subj "/CN=server_node/OU=interop-ed448" \
        -addext "subjectAltName=DNS:server_node" \
    && ln -sf certs/cert_rsa.pem /app/cert.pem \
    && ln -sf certs/key_rsa.pem /app/key.pem

EXPOSE 50051
EXPOSE 5555

CMD ["python3", "/app/wrapper_entry.py"]
