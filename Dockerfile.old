FROM debian:stretch AS build

ENV BCC_VERSION=0.10.0
RUN echo "deb http://deb.debian.org/debian stretch non-free" > /etc/apt/sources.list.d/non-free.list \
        && apt-get update \
        && apt-get install -y  --no-install-recommends \
            debhelper \
            build-essential \
            cmake \
            fakeroot \
            libllvm3.8\
            llvm-3.8-dev\
            libclang-3.8-dev \
            libelf-dev \
            bison \
            flex \
            git \
            sudo \
            libedit-dev \
            clang-format-3.8 \
            ca-certificates \
            python3 \
            python-netaddr \
            python-pyroute2 \
            luajit \
            libluajit-5.1-dev \
            arping \
            netperf \
            iperf \
            ethtool \
            devscripts \
            zlib1g-dev \
            libfl-dev\
        && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/local/src
RUN git clone -b v${BCC_VERSION} https://github.com/iovisor/bcc.git \
        && cd bcc \
        && debuild -b -uc -us

COPY php_tool.py /usr/local/bin/
