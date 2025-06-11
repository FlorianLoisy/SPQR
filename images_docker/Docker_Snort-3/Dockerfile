FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV SNORT_VERSION=3.1.77.0
ENV DAQ_VERSION=3.0.11

# Installation des dépendances
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libpcap-dev \
    libpcre3-dev \
    libdumbnet-dev \
    bison \
    flex \
    zlib1g-dev \
    liblzma-dev \
    openssl \
    libssl-dev \
    libhwloc-dev \
    libluajit-5.1-dev \
    libunwind-dev \
    libfl-dev \
    libhyperscan-dev \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# Installation de libdaq
RUN wget https://github.com/snort3/libdaq/archive/refs/tags/v${DAQ_VERSION}.tar.gz && \
    tar -xvzf v${DAQ_VERSION}.tar.gz && \
    cd libdaq-${DAQ_VERSION} && \
    ./bootstrap && \
    ./configure && \
    make && \
    make install && \
    cd .. && \
    rm -rf libdaq-${DAQ_VERSION}* && \
    ldconfig

# Installation de Snort 3
RUN wget https://github.com/snort3/snort3/archive/refs/tags/${SNORT_VERSION}.tar.gz && \
    tar -xvzf ${SNORT_VERSION}.tar.gz && \
    cd snort3-${SNORT_VERSION} && \
    ./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc && \
    cd build && \
    make -j$(nproc) && \
    make install && \
    cd ../.. && \
    rm -rf snort3-${SNORT_VERSION}* && \
    ldconfig

# Configuration de base
RUN mkdir -p /etc/snort/rules && \
    mkdir -p /var/log/snort && \
    mkdir -p /usr/local/etc/snort && \
    mkdir -p /usr/local/lib/snort_extra

# Vérification de l'installation
RUN snort -V

# Point d'entrée par défaut
ENTRYPOINT ["snort"]
CMD ["-V"]

