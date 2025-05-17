FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    libpcap-dev \
    libpcre3-dev \
    libdumbnet-dev \
    bison \
    flex \
    zlib1g-dev \
    liblzma-dev \
    wget \
    libluajit-5.1-dev \
    luajit \
    autotools-dev \
    libtool \
    libssl-dev \
    libnghttp2-dev \
    libhwloc-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# DAQ installation
RUN wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz && \
    tar -xvzf daq-2.0.7.tar.gz && \
    cd daq-2.0.7 && \
    ./configure && make && make install && \
    cd .. && rm -rf daq-2.0.7*

# Snort 2.9 installation
RUN wget https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz && \
    tar -xvzf snort-2.9.20.tar.gz && \
    cd snort-2.9.20 && \
    ./configure --enable-sourcefire --with-luajit && \
    make && make install && \
    ldconfig && \
    ln -s /usr/local/bin/snort /usr/sbin/snort && \
    cd .. && rm -rf snort-2.9.20*

CMD ["snort", "-V"]

