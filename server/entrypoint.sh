#!/usr/bin/env bash
set -euo pipefail

SERVER_IP="10.10.0.10"
HOSTNAME="tls-lab.local"
SSLDIR="/etc/ssl/tls-lab"

# Create lab CA
if [ ! -f /opt/tlslab/lab-rootCA.key ]; then
  openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
    -keyout /opt/tlslab/lab-rootCA.key -out /opt/tlslab/lab-rootCA.crt \
    -subj "/CN=lab-rootCA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
fi

# Create server key and CSR and sign with CA
openssl genpkey -algorithm RSA -out /opt/tlslab/tls-lab.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key /opt/tlslab/tls-lab.key -out /opt/tlslab/tls-lab.csr -subj "/CN=${HOSTNAME}"

cat > /opt/tlslab/v3ext.cnf <<EOF
subjectAltName=DNS:${HOSTNAME},IP:${SERVER_IP}
EOF

openssl x509 -req -in /opt/tlslab/tls-lab.csr -CA /opt/tlslab/lab-rootCA.crt -CAkey /opt/tlslab/lab-rootCA.key \
  -CAcreateserial -out /opt/tlslab/tls-lab.crt -days 365 -sha256 -extfile /opt/tlslab/v3ext.cnf

# fullchain
cat /opt/tlslab/tls-lab.crt /opt/tlslab/lab-rootCA.crt > /opt/tlslab/tls-lab-fullchain.pem

# copy certs to ssl dir
mkdir -p ${SSLDIR}
cp /opt/tlslab/tls-lab.key ${SSLDIR}/tls-lab.key
cp /opt/tlslab/tls-lab.crt ${SSLDIR}/tls-lab.crt
cp /opt/tlslab/tls-lab-fullchain.pem ${SSLDIR}/tls-lab-fullchain.pem
cp /opt/tlslab/lab-rootCA.crt ${SSLDIR}/lab-rootCA.crt

# enable nginx sites
ln -sf /etc/nginx/sites-available/tls-vulnerable /etc/nginx/sites-enabled/tls-vulnerable
ln -sf /etc/nginx/sites-available/tls-hardened /etc/nginx/sites-enabled/tls-hardened
rm -f /etc/nginx/sites-enabled/default

# ensure web root exists
chown -R www-data:www-data /var/www/tls-lab

# reload nginx
nginx -t
service nginx restart

# Keep container running (nginx is the service)
tail -f /var/log/nginx/access.log /var/log/nginx/error.log
