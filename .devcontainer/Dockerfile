FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    fuse3 \
    git \
    gnupg \
    libfuse3-dev \
    pass \
    pkg-config \
    python3 \
    sudo \
    xz-utils \
  && rm -rf /var/lib/apt/lists/*

RUN usermod -s /bin/bash ubuntu \
  && printf '%s\n' 'ubuntu ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/ubuntu \
  && chmod 0440 /etc/sudoers.d/ubuntu

WORKDIR /workspaces/file-snitch

COPY build.zig build.zig.zon ./
COPY .devcontainer/scripts/setup.sh ./.devcontainer/scripts/setup.sh

USER ubuntu
RUN ./.devcontainer/scripts/setup.sh --skip-packages
