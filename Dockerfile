FROM fedora:39

# Install dependencies
RUN dnf install -y python3 python3-pip openssl gnutls-utils && dnf clean all
RUN pip3 install grpcio grpcio-tools

WORKDIR /app

# Copy all files (proto, wrapper, generated code)
COPY . .

# Generate certificates inside the image for the PoC
RUN openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=server_node"

# Control port for gRPC, Data port for TLS
EXPOSE 50051
EXPOSE 5555

CMD ["python3", "wrapper_openssl.py"]