# Use a single, robust base image to guarantee compatibility
FROM python:3.9-slim

# Install ALL build and runtime dependencies in one go
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    ninja-build \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 1. Build liboqs (C Library)
WORKDIR /build
RUN git clone --branch main --single-branch --depth 1 https://github.com/open-quantum-safe/liboqs.git \
    && mkdir liboqs/build && cd liboqs/build \
    && cmake -GNinja -DOQS_USE_OPENSSL=1 -DCMAKE_INSTALL_PREFIX=/usr/local .. \
    && ninja && ninja install

# 2. Build liboqs-python (Python Wrapper)
WORKDIR /build
RUN git clone --branch main --single-branch --depth 1 https://github.com/open-quantum-safe/liboqs-python.git \
    && cd liboqs-python \
    && pip install .

# 3. Install App Dependencies
RUN pip install fastapi uvicorn requests spiffe cryptography pycryptodome jinja2 python-multipart

# 4. Critical Linker Configuration
# Force Linux to index the new library immediately
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/local.conf && ldconfig

# Set Environment variables to ensure Python finds it
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PYTHONPATH=$PYTHONPATH:/usr/local/lib/python3.9/site-packages

# Setup App
WORKDIR /app
COPY . /app

# Run as root
USER root

CMD ["python3", "main.py"]