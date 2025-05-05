FROM ubuntu:latest

# Install necessary packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    nginx \
    vsftpd \
    postfix \
    bind9 \
    net-tools \
    vim \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# SSH Configuration
RUN mkdir -p /run/sshd
RUN echo 'root:your_secure_password' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# HTTP Configuration (Nginx)
RUN echo "<h1>Flag for HTTP: POKHARA_HTTP_FLAG</h1>" > /var/www/html/index.html

# FTP Configuration (vsftpd)
RUN echo "Welcome to the FTP server. Flag is in /home/ftp/flag.txt" > /etc/vsftpd.conf
RUN useradd -d /home/ftp -s /bin/bash ftpuser
RUN echo 'ftpuser:your_secure_ftp_password' | chpasswd
RUN mkdir -p /home/ftp
RUN echo "POKHARA_FTP_FLAG" > /home/ftp/flag.txt
RUN chown -R ftpuser:nogroup /home/ftp
RUN chmod 755 /home/ftp
RUN chmod 644 /home/ftp/flag.txt

# SMTP Configuration (Postfix - Minimal Configuration for Receiving)
RUN dpkg-reconfigure --frontend noninteractive postfix
RUN sed -i 's/inet_interfaces = all/inet_interfaces = all/' /etc/postfix/main.cf
RUN echo "Flag for SMTP: POKHARA_SMTP_FLAG" > /etc/postfix/banner

# DNS Configuration (BIND9 - Simple Forward Zone for example.com)
RUN echo "options { directory \"/var/cache/bind\"; };" > /etc/bind/named.conf.options
RUN echo "zone \"example.com\" { type master; file \"/etc/bind/db.example.com\"; };" > /etc/bind/named.conf.local
RUN echo "zone \"0.0.127.in-addr.arpa\" { type master; file \"/etc/bind/db.127\"; };" >> /etc/bind/named.conf.local
RUN echo "\$TTL 86400\n@ IN SOA ns1.example.com. admin.example.com. ( 2023043000 3600 900 604800 86400 )\n@ IN NS ns1.example.com.\n@ IN A 127.0.0.1\nns1 IN A 127.0.0.1\nwww IN A 127.0.0.1\nflag.example.com IN TXT \"Flag for DNS: POKHARA_DNS_FLAG\"" > /etc/bind/db.example.com
RUN echo "\$TTL 86400\n@ IN SOA localhost. root.localhost. ( 1 3600 900 604800 86400 )\n@ IN NS localhost.\n1 IN PTR localhost." > /etc/bind/db.127

# Expose Ports
EXPOSE 22 80 21 110 143 25 53/tcp 53/udp

# Start Services
CMD /bin/bash -c "service ssh start && \
    service nginx start && \
    service vsftpd start && \
    service postfix start && \
    service named start && \
    tail -f /dev/null"