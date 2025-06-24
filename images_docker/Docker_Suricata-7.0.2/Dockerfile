# Utilisez une image de base
FROM debian:bookworm-slim

# Installez les dépendances nécessaires pour compiler Suricata
RUN apt-get update && apt-get install -y \
    build-essential \
    libpcre3 \
    libpcre3-dbg \
    libpcre3-dev \
    libpcap-dev \
    libnet1-dev \
    libyaml-0-2 \
    libyaml-dev \
    liblz4-dev\ 
    zlib1g \
    zlib1g-dev \
    libcap-ng-dev \
    libcap-ng0 \
    make \
    libmagic-dev \
    libjansson-dev \
    libnss3-dev \
    libgeoip-dev \
    liblua5.1-0-dev \
    libhiredis-dev \
    libevent-dev \
    libluajit-5.1-dev \
    rustc\
    cargo\  
    wget \
    python3-pip \
    procps \   
    libtool \ 
    libpcre2-dev \ 
    && rm -rf /var/lib/apt/lists/*

# Copiez et extrayez les sources de Suricata
ADD images_docker/Docker_Suricata-7.0.2/suricata-7.0.2.tar.gz /tmp/
WORKDIR /tmp/suricata-7.0.2

# Configurez, compilez et installez Suricata
RUN ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-lua --enable-profiling --disable-gccmarch-native &&\
    make &&\
    make install-full

# Mise à jour de Suricata
#COPY config/suricata_7.0.2/suricata.yaml /etc/suricata/suricata.yaml
#COPY config/suricata_7.0.2/classification.config /etc/suricata/classification.config
#COPY config/suricata_7.0.2/reference.config /etc/suricata/reference.config
#COPY config/suricata_7.0.2/rules/suricata.rules /etc/suricata/rules/suricata.rules
#RUN /etc/suricata/suricata-update.sh

# Nettoyez 
WORKDIR /
RUN apt-get clean -y && rm -rf /tmp/suricata-7.0.2

