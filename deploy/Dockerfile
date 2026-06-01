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
COPY scripts/gen_interop_certs.sh ./scripts/

RUN bash ./scripts/gen_interop_certs.sh \
    && ln -sf certs/rsa_default.crt /app/cert.pem \
    && ln -sf certs/rsa_default.key /app/key.pem

EXPOSE 50051 50052 50053
EXPOSE 5555

CMD ["python3", "/app/wrapper_entry.py"]
