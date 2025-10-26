FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y nginx openssl curl vim ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /opt/tlslab /etc/ssl/tls-lab /var/www/tls-lab

COPY tls-hardened /etc/nginx/sites-available/tls-hardened
COPY tls-vulnerable /etc/nginx/sites-available/tls-vulnerable
COPY entrypoint.sh /opt/tlslab/entrypoint.sh
COPY index-vulnerable.html /var/www/tls-lab/index-vulnerable.html
COPY index-hardened.html /var/www/tls-lab/index-hardened.html

RUN chmod +x /opt/tlslab/entrypoint.sh

EXPOSE 80 8443 9443

CMD ["/opt/tlslab/entrypoint.sh"]
