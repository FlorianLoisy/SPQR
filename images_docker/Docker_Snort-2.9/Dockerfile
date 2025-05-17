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
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

RUN wget https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz && \
    tar -xvzf daq-2.0.6.tar.gz && \
    cd daq-2.0.6 && \
    ./configure && \
    make && \
    make install && \
    cd .. && \
    wget https://www.snort.org/downloads/snort/snort-2.9.15.tar.gz && \
    tar -xvzf snort-2.9.15.tar.gz && \
    cd snort-2.9.15 && \
    ./configure --enable-sourcefire && \
    make && \
    make install && \
    ldconfig && \
    ln -s /usr/local/bin/snort /usr/sbin/snort

CMD ["snort", "-V"]
