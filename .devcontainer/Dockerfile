FROM gcc:16

ARG UID=1000
ARG USERNAME=dev

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    build-essential \
    cmake \
    ninja-build \
    git \
    curl \
    pkg-config \
    clang \
    clang-tidy \
    clang-format \
    # Debugger + profiling
    gdb \
    valgrind \
    linux-perf \
    # netprobe system deps
    libpcap-dev \
    libudev-dev \
    libcap2-bin \
    # Utilities
    sudo \
    vim \
    less \
    iproute2 \
    iputils-ping \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Install Conan 2 via uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

ENV UV_TOOL_DIR=/opt/uv/tools
ENV UV_TOOL_BIN_DIR=/usr/local/bin
ENV UV_PYTHON_PREFERENCE=only-system

RUN mkdir -p /opt/uv/tools \
    && uv tool install conan

# Create non-root user
RUN useradd -m -u ${UID} -s /bin/bash ${USERNAME} \
    && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers


USER ${USERNAME}

WORKDIR /workspace

CMD ["/bin/bash"]
