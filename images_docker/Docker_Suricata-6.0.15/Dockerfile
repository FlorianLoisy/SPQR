# Utilisez une image de base
FROM debian:bullseye-slim

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
    && rm -rf /var/lib/apt/lists/*

# Copiez et extrayez les sources de Suricata
ADD images_docker/Docker_Suricata-6.0.15/suricata-6.0.15.tar.gz /tmp/
WORKDIR /tmp/suricata-6.0.15

# Configurez, compilez et installez Suricata
RUN ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-luajit --enable-profiling --disable-gccmarch-native &&\
    make &&\
    make install

# Mise à jour de Suricata
#RUN pip3 install --pre --upgrade suricata-update PyYAML
#COPY ressources/suricata/suricata-update.sh /etc/suricata/suricata-update.sh
#RUN chmod +x /etc/suricata/suricata-update.sh
COPY config/suricata_6.0.15/suricata.yaml /etc/suricata/suricata.yaml
COPY config/suricata_6.0.15/classification.config /etc/suricata/classification.config
COPY config/suricata_6.0.15/reference.config /etc/suricata/reference.config
COPY config/suricata_6.0.15/rules/suricata.rules /etc/suricata/rules/suricata.rules
#RUN /etc/suricata/suricata-update.sh

# Nettoyez 
WORKDIR /
RUN apt-get clean -y && rm -rf /tmp/suricata-6.0.15
