FROM fedora:39

# Install dependencies
RUN dnf install -y python3 python3-pip openssl gnutls-utils && dnf clean all
RUN pip3 install grpcio grpcio-tools

WORKDIR /app

# Copy all files (proto, wrapper, generated code)
COPY interop_pb2.py interop_pb2_grpc.py ./
# Copy both wrappers and driver (server_node=OpenSSL, client_node=GnuTLS for interop)
COPY src/wrappers/wrapper_openssl.py src/wrappers/wrapper_gnutls.py ./
COPY src/driver/driver.py ./
# Generate certificates in the image (no host certs required for build)
RUN openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=server_node"

# Control port for gRPC, Data port for TLS
EXPOSE 50051
EXPOSE 5555

CMD ["python3", "wrapper_openssl.py"]