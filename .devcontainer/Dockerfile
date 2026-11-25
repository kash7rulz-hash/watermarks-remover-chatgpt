FROM mcr.microsoft.com/devcontainers/python:3.14-bookworm

USER root

ARG C2PATOOL_VERSION=c2patool-v0.27.15
ARG C2PATOOL_SHA256=7a035b727a6cdda8ad08d98fe94b3c20febee4aea4e7c1de02571b295730faf0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        ffmpeg \
        ghostscript \
        libarchive-zip-perl \
        libimage-exiftool-perl \
        qpdf \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/c2patool.tar.gz \
        "https://github.com/contentauth/c2pa-rs/releases/download/${C2PATOOL_VERSION}/${C2PATOOL_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
    && echo "${C2PATOOL_SHA256}  /tmp/c2patool.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/c2patool.tar.gz -C /tmp \
    && install -m 0755 /tmp/c2patool/c2patool /usr/local/bin/c2patool \
    && rm -rf /tmp/c2patool /tmp/c2patool.tar.gz

RUN python3 -m pip install --no-cache-dir "mcp>=2,<3" "uvicorn>=0.34,<1"

USER vscode
