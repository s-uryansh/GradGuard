FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    bash \
    coreutils \
    net-tools \
    curl \
    wget \
    python3 \
    vim \
    bsdutils \
    && rm -rf /var/lib/apt/lists/*

RUN echo 'root:root' | chpasswd
WORKDIR /root