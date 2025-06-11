FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV SNORT_VERSION=3.1.50.0
ENV DAQ_VERSION=3.0.9

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
    libtool \
    autoconf \
    pkg-config \
    libsystemd-dev \
    wget \
    git \
    patch \
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
    # Patch for oops_handler.cc
    sed -i 's/daq_msg_get_priv_data/daq_msg_get_data/g' src/main/oops_handler.cc && \
    # Patch for GENEVE capability
    sed -i 's/DAQ_CAPA_DECODE_GENEVE/DAQ_CAPA_DECODE_TEREDO/g' src/packet_io/sfdaq_instance.cc && \
    ./configure_cmake.sh --prefix=/usr/local \
        --enable-debug \
        --disable-tcmalloc \
        --enable-debug-msgs && \
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

