# Nginx reverse proxy for CTF-Server

This directory holds the Nginx reverse proxy configuration and TLS materials for Cloudflare Origin Certificates.

## Files

- `conf.d/default.conf`
  - Nginx server config: HTTP->HTTPS redirect, TLS, gzip, and proxy to the `web` service.
- `certs/origin.crt`
  - Place your Cloudflare Origin Certificate PEM here.
- `certs/origin.key`
  - Place your private key for the Origin Certificate here (PEM). Keep this secret.

## How to create a Cloudflare Origin Certificate

1. In Cloudflare dashboard, go to your domain → SSL/TLS → Origin Server → Create Certificate.
2. Choose *Cloudflare Origin Certificate*.
3. Download/save the certificate (PEM) and private key (PEM).
4. Save them as:
   - `nginx/certs/origin.crt`
   - `nginx/certs/origin.key`

Ensure file permissions are safe (the key should be readable only by you locally).

## Running with docker-compose

From the repository root:

```powershell
# Build and start both services
docker compose up --build
```

- Nginx listens on ports 80 and 443 on the host and proxies to the Flask app (`web:5000`).
- The Flask app listens internally on 0.0.0.0:5000.
- Gzip is enabled and static assets under `/static/` are cached aggressively.

## Notes

- If you do not want to bind to privileged ports locally, change the Compose `ports:` mapping (e.g., `8443:443`).
- The Flask app already trusts proxy headers and sets secure cookie flags when not in development.
- You can further restrict client IPs or trust Cloudflare networks by adding `set_real_ip_from` directives with Cloudflare IP ranges if needed.
