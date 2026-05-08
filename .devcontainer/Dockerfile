FROM debian:bookworm-slim

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
    # Compiler
    gcc \
    g++ \
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
ENV UV_PYTHON_PREFERENCE=system

RUN uv python install
RUN uv tool install conan

# Create non-root user
RUN useradd -m -u ${UID} -s /bin/bash ${USERNAME} \
    && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Give user access to raw sockets without sudo
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump || true

USER ${USERNAME}
RUN conan --help

WORKDIR /workspace

# Set Conan to auto-install system packages
RUN conan config set tools.system.package_manager:mode=install && \
    conan config set tools.system.package_manager:sudo=True || true

# Conan cache lives inside the mounted workspace so it survives rebuilds
ENV CONAN_HOME=/workspace/.conan2

CMD ["/bin/bash"]
