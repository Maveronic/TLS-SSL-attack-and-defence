# TLS Lab - README
Work done by:
- Mgbemena Mmesomachukwu Chukwuemeka
- Nikita Nekhai
  
Quick: clone → build → run → scan

---

## 1. Clone the repository
```bash
git clone https://github.com/Maveronic/TLS-SSL-attack-and-defence
cd TLS-SSL-attack-and-defence
```

---

## 2. Build and start the Docker stack
```bash
docker-compose build
docker-compose up -d
```

---

## 3. Access the web hosts
- Vulnerable host: `https://localhost:8443`  
- Hardened host: `https://localhost:9443`

---

## 4. Run TLS scanners

### testssl.sh
```bash
# Vulnerable
testssl localhost:8443

# Hardened
testssl localhost:9443
```

### sslyze
```bash
# Vulnerable
sslyze localhost:8443

# Hardened
sslyze localhost:9443
```

---

## 5. Burp Suite (Firefox) — intercepting local hosts

1. In Firefox set the special pref so `localhost` traffic goes through the proxy:
   - Open `about:config`
   - Search for `network.proxy.allow_hijacking_localhost`
   - Set it to `true`

2. Configure Firefox proxy:
   - Preferences → Network Settings → **Manual proxy configuration**
     - HTTP Proxy: `127.0.0.1`  Port: `8080`
     - HTTPS Proxy: `127.0.0.1` Port: `8080`
     - (Optional) Check **Use this proxy server for all protocols**
   - Remove `localhost` and `127.0.0.1` from the **No proxy for** field if present.

3. Start Burp and ensure Proxy Listener is active on `127.0.0.1:8080`.  
4. Browse to `https://localhost:8443` or `https://localhost:9443` — Burp should see the requests (you may need to import Burp’s CA into Firefox to avoid certificate warnings).
5. Importing the certifciate can be done by visiting `http://burpsuite' and downloading the certificate (CA)
6. Next, go to Firefox settings:
   - Go to `Privacy and Security`
   - On the section, go to `certificates` and select 'View certificates`
   - There, use the `Import` feature and add the download Burp CA
