FROM fedora:39

# Install dependencies (nss-tools for NSS wrapper)
RUN dnf install -y python3 python3-pip openssl gnutls-utils nss-tools socat coreutils && dnf clean all
# Runtime Python deps for wrappers + driver.
RUN pip3 install 'grpcio>=1.80.0' 'protobuf>=4.21'

WORKDIR /app

# Schema + generated protobuf/gRPC Python
COPY proto/ ./proto/
# Copy wrappers and driver
COPY src/wrappers/*.py ./
COPY src/driver/scenarios.py src/driver/driver.py ./
COPY src/tests ./tests/
# Runtime wrapper selection + static config
COPY deploy/wrapper_entry.py deploy/wrappers.json ./
# Generate certificates (NSS DB is created lazily in wrapper_nss.py)
RUN openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=server_node"

# Control port for gRPC, Data port for TLS
EXPOSE 50051
EXPOSE 5555

CMD ["python3", "/app/wrapper_entry.py"]