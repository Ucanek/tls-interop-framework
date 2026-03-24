FROM fedora:39

# Install dependencies (nss-tools for NSS wrapper)
RUN dnf install -y python3 python3-pip openssl gnutls-utils nss-tools socat coreutils && dnf clean all
RUN pip3 install grpcio grpcio-tools

WORKDIR /app

# Copy all files (proto, wrapper, generated code)
COPY interop_pb2.py interop_pb2_grpc.py ./
# Copy wrappers, driver, and NSS DB setup script
COPY src/wrappers/wrapper_openssl.py src/wrappers/wrapper_gnutls.py src/wrappers/wrapper_nss.py ./
COPY src/driver/driver.py ./
COPY scripts/setup_nssdb.sh ./
# Generate certificates and NSS DB (for wrapper_nss.py)
RUN openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=server_node" \
  && chmod +x setup_nssdb.sh && NSSDB=/app/nssdb ./setup_nssdb.sh

# Control port for gRPC, Data port for TLS
EXPOSE 50051
EXPOSE 5555

CMD ["python3", "wrapper_openssl.py"]