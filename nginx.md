# NGINX Configuration Reference (HTTP + STREAM + MAIL)

Comprehensive reference including **Directive**, **Default**, **Possible Values**, **Best Practice**, and **Description**.  
Suitable for DevOps, SRE, and Production-grade deployment.

---

# 📑 TABLE OF CONTENTS

1. [HTTP Core Directives](#1-http-core-directives)
2. [Server & Location Directives](#2-server--location-directives)
3. [Proxy Module](#3-proxy-module)
4. [WebSocket Directives](#4-websocket-directives)
5. [SSL / TLS Module](#5-ssl--tls-module)
6. [Gzip Module](#6-gzip-module)
7. [Caching Module](#7-caching-module)
8. [Upstream Load Balancing](#8-upstream-load-balancing)
9. [Security Headers](#9-security-headers)
10. [Rate Limiting](#10-rate-limiting)
11. [Logging Module](#11-logging-module)
12. [STREAM TCP/UDP Module](#12-stream-module)
13. [MAIL Proxy Module](#13-mail-proxy-module)

---

# 1. HTTP CORE DIRECTIVES

| Directive            | Default | Possible Values | Best Practice                        | Description                |
| -------------------- | ------- | --------------- | ------------------------------------ | -------------------------- |
| client_max_body_size | 1m      | size            | Set 50m–200m for APIs with uploads   | Max allowed request body   |
| keepalive_timeout    | 75s     | seconds         | Keep default unless long connections | Idle keepalive duration    |
| sendfile             | off     | on/off          | Enable for static file serving       | Kernel-level file transfer |
| tcp_nodelay          | on      | on/off          | Keep enabled                         | Disable Nagle's algo       |
| tcp_nopush           | off     | on/off          | Enable with sendfile                 | Optimize packet flow       |
| include              | —       | file path       | Use modular config                   | Include extra config files |
| send_timeout         | 60s     | seconds         | Raise for slow clients               | Client write timeout       |

---

# 2. SERVER & LOCATION DIRECTIVES

| Directive   | Default    | Possible Values     | Best Practice                     | Description               |
| ----------- | ---------- | ------------------- | --------------------------------- | ------------------------- |
| listen      | —          | port, ip:port, unix | Always specify explicit IP + port | Server listening socket   |
| server_name | ""         | domains, wildcard   | Avoid `_`; use exact names        | Domain matching           |
| root        | —          | path                | Only for static sites             | Document root             |
| index       | index.html | file list           | As needed                         | Default served file       |
| try_files   | —          | files, fallback     | Required for SPA                  | Try paths or redirect     |
| return      | —          | code, text          | Use for redirects                 | Return immediate response |
| rewrite     | —          | regex → replacement | Use minimally                     | URL rewrite engine        |

---

# 3. PROXY MODULE

| Directive                  | Default | Possible Values | Best Practice             | Description              |
| -------------------------- | ------- | --------------- | ------------------------- | ------------------------ |
| proxy_pass                 | —       | URL             | Always specify protocol   | Send request to upstream |
| proxy_http_version         | 1.0     | 1.0, 1.1        | ALWAYS 1.1 for WS         | Upstream HTTP version    |
| proxy_set_header           | —       | $vars, strings  | Set Host, X-Real-IP...    | Modify upstream headers  |
| proxy_pass_request_body    | on      | on/off          | Leave on for APIs         | Forward body             |
| proxy_pass_request_headers | on      | on/off          | Leave on                  | Forward headers          |
| proxy_read_timeout         | 60s     | seconds         | Set 3600s for WS          | Upstream read timeout    |
| proxy_send_timeout         | 60s     | seconds         | Raise if needed           | Upstream send timeout    |
| proxy_connect_timeout      | 60s     | seconds         | Set 10s for fail-fast     | Upstream connect timeout |
| proxy_buffering            | on      | on/off          | Off for WS/SSE            | Response buffering       |
| proxy_buffer_size          | 4k/8k   | size            | Increase if large headers | Header buffer            |
| proxy_buffers              | 8 4k    | N size          | Increase for large resp.  | Body buffers             |
| proxy_redirect             | default | off or rules    | Off for API               | Rewrite Location header  |
| proxy_intercept_errors     | off     | on/off          | On for custom error pages | Catch upstream errors    |

---

# 4. WEBSOCKET DIRECTIVES

> **IMPORTANT UPDATE (WebSocket Support):**  
> NGINX does **not** automatically provide the `$connection_upgrade` variable.  
> You MUST define this mapping inside the `http {}` block:

```nginx
http {
    map $http_upgrade $connection_upgrade {
        default upgrade;
        ''      close;
    }
}
```

Then use inside your `server` block:

```nginx
proxy_ssl_server_name on;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $connection_upgrade;
```

This is the correct and recommended production setup.

| Directive                   | Default | Possible Values       | Best Practice | Description            |
| --------------------------- | ------- | --------------------- | ------------- | ---------------------- |
| proxy_http_version          | 1.0     | 1.1                   | MUST be 1.1   | WebSocket upgrade      |
| proxy_set_header Upgrade    | —       | $http_upgrade         | Required      | Upgrade header         |
| proxy_set_header Connection | —       | upgrade or mapped var | Required      | WS handshake           |
| proxy_read_timeout          | 60s     | seconds               | Use 3600s     | WS long connection     |
| proxy_buffering             | on      | on/off                | MUST be off   | Realtime communication |

---

# 5. SSL / TLS MODULE

| Directive                 | Default               | Possible Values  | Best Practice       | Description               |
| ------------------------- | --------------------- | ---------------- | ------------------- | ------------------------- |
| ssl_certificate           | —                     | PEM file         | Use Let's Encrypt   | Certificate path          |
| ssl_certificate_key       | —                     | key file         | Protect permissions | Private key               |
| ssl_protocols             | TLSv1 TLSv1.1 TLSv1.2 | TLSv1.2, TLSv1.3 | Only 1.2+           | Allowed TLS versions      |
| ssl_ciphers               | large list            | cipher list      | Use Mozilla modern  | Ciphers                   |
| ssl_prefer_server_ciphers | off                   | on/off           | On                  | Force server cipher order |
| ssl_session_cache         | off                   | shared:SSL:size  | Enable              | TLS session cache         |
| ssl_session_timeout       | 5m                    | time             | Keep                | Session TTL               |
| ssl_ecdh_curve            | auto                  | curves           | Use X25519          | ECDH curve                |
| ssl_stapling              | off                   | on/off           | On                  | OCSP stapling             |
| ssl_stapling_verify       | off                   | on/off           | On                  | Verify OCSP               |

---

# 6. GZIP MODULE

| Directive       | Default | Possible Values | Best Practice | Description               |
| --------------- | ------- | --------------- | ------------- | ------------------------- |
| gzip            | off     | on/off          | On            | Enable compression        |
| gzip_types      | —       | MIME types      | json, js, css | What to compress          |
| gzip_min_length | 20      | bytes           | Keep default  | Minimum size              |
| gzip_comp_level | 1       | 1–9             | Use 4–5       | Compression level         |
| gzip_proxied    | off     | any, expired... | any           | Compress proxied requests |

---

# 7. CACHING MODULE

| Directive             | Default | Possible Values | Best Practice         | Description    |
| --------------------- | ------- | --------------- | --------------------- | -------------- |
| proxy_cache           | —       | cache zone      | Use named cache       | Enable caching |
| proxy_cache_path      | —       | path + params   | Use SSD               | Cache storage  |
| proxy_cache_valid     | —       | code TTL        | Cache 200/302 for 10m | TTL rules      |
| proxy_cache_use_stale | —       | error, timeout  | Use stale-if-error    | Serve stale    |
| proxy_no_cache        | —       | condition       | For logged-in users   | Disable cache  |
| proxy_cache_bypass    | —       | condition       | Same as above         | Skip cache     |

---

# 8. UPSTREAM LOAD BALANCING

| Directive        | Default | Possible Values | Best Practice         | Description       |
| ---------------- | ------- | --------------- | --------------------- | ----------------- |
| upstream NAME {} | —       | server list     | Use least_conn        | LB group          |
| server           | —       | ip:port, weight | Use multiple          | Backend server    |
| least_conn       | —       | flag            | Good for even traffic | LB algo           |
| ip_hash          | —       | flag            | Sticky sessions       | Hash by IP        |
| keepalive        | —       | number          | Use 100               | Reuse connections |

---

# 9. SECURITY HEADERS

| Directive                            | Default | Possible Values  | Best Practice                   | Description          |
| ------------------------------------ | ------- | ---------------- | ------------------------------- | -------------------- |
| add_header X-Frame-Options           | —       | DENY, SAMEORIGIN | SAMEORIGIN                      | Prevent clickjacking |
| add_header X-Content-Type-Options    | —       | nosniff          | nosniff                         | Prevent MIME sniff   |
| add_header Referrer-Policy           | —       | policies         | strict-origin-when-cross-origin | Referrer control     |
| add_header Strict-Transport-Security | —       | max-age          | 31536000 preload                | Enforce HTTPS        |

---

# 10. RATE LIMITING

| Directive       | Default | Possible Values | Best Practice        | Description            |
| --------------- | ------- | --------------- | -------------------- | ---------------------- |
| limit_req_zone  | —       | zone=size rate  | Define per-IP limits | Create rate zone       |
| limit_req       | —       | zone burst      | Use for APIs         | Apply rate limit       |
| limit_conn_zone | —       | zone            | Group connections    | Connection limiting    |
| limit_conn      | —       | number          | Protect backend      | Max concurrent per key |

---

# 11. LOGGING MODULE

| Directive  | Default     | Possible Values   | Best Practice    | Description      |
| ---------- | ----------- | ----------------- | ---------------- | ---------------- |
| access_log | on          | off, file, format | Use JSON logs    | HTTP logs        |
| error_log  | stderr warn | levels            | Use error/warn   | Error logs       |
| log_format | —           | custom formats    | JSON recommended | Custom log style |

---

# 12. STREAM MODULE (TCP/UDP)

| Directive             | Default | Possible Values | Best Practice     | Description          |
| --------------------- | ------- | --------------- | ----------------- | -------------------- |
| stream {}             | —       | block           | Use separate file | Enable TCP/UDP proxy |
| proxy_pass            | —       | ip:port         | MySQL, Redis      | Forward TCP/UDP      |
| proxy_connect_timeout | 60s     | time            | 10s               | TCP connect timeout  |
| proxy_timeout         | 10m     | time            | Tune per protocol | Read/write timeout   |
| listen                | —       | port            | Example: 3306     | Listen for stream    |

---

# 13. MAIL PROXY MODULE

| Directive                | Default | Possible Values | Best Practice        | Description         |
| ------------------------ | ------- | --------------- | -------------------- | ------------------- |
| mail {}                  | —       | block           | Use only when needed | Enable MAIL proxy   |
| auth_http                | —       | URL             | External auth        | Authenticate users  |
| proxy_pass_error_message | off     | on/off          | Keep off             | Hide backend errors |
| starttls                 | —       | on/off          | Require for SMTP     | Enable TLS          |

---

# ✔ END OF DOCUMENT

---

# 14. EXAMPLE CONFIGS — Practical examples by group

Below are practical, ready-to-use Nginx config snippets you can drop into `/etc/nginx/sites-available/` (or include files). Each snippet is small, focused, and annotated.

## 14.1 HTTP Core — minimal performant server

```nginx
# /etc/nginx/sites-available/example-core.conf
server {
    listen 80;
    server_name example.com www.example.com;
    root /var/www/example.com/html;
    index index.html index.htm;

    # Increase upload size
    client_max_body_size 100m;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;

    location / {
        try_files $uri $uri/ =404;
    }
}
```

## 14.2 Server & Location — SPA + fallback to index.html

```nginx
server {
    listen 80;
    server_name app.example.com;

    root /srv/app/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # static caching
    location ~* \.(?:css|js|jpg|jpeg|png|gif|ico|svg)$ {
        expires 7d;
        add_header Cache-Control "public, max-age=604800";
    }
}
```

## 14.3 Proxy Module — reverse proxy to Node.js app

```nginx
upstream node_app {
    server 127.0.0.1:3000;
    server 127.0.0.1:3001;
    keepalive 32;
}

server {
    listen 80;
    server_name api.example.com;

    location / {
        proxy_pass http://node_app;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 300s;

        proxy_buffering on;
    }
}
```

## 14.4 WebSocket — socket.io reverse proxy

```nginx
server {
    listen 443 ssl;
    server_name ws.example.com;

    ssl_certificate /etc/letsencrypt/live/ws.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ws.example.com/privkey.pem;

    location /socket.io/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_buffering off;
        proxy_read_timeout 3600s;
    }
}
```

## 14.5 SSL / TLS — secure modern TLS config (recommended)

```nginx
# snippet: /etc/nginx/snippets/ssl-params.conf
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...';
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_ecdh_curve X25519:P-256;
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=30s;
resolver_timeout 5s;
```

## 14.6 Gzip — enable for APIs and static assets

```nginx
http {
    gzip on;
    gzip_min_length 1000;
    gzip_comp_level 4;
    gzip_types text/plain text/css application/javascript application/json application/xml text/xml;
    gzip_vary on;
}
```

## 14.7 Caching — proxy_cache example for backend caching

```nginx
http {
    proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:10m max_size=10g inactive=60m use_temp_path=off;

    server {
        listen 80;
        server_name cache.example.com;

        location / {
            proxy_cache my_cache;
            proxy_cache_valid 200 302 10m;
            proxy_cache_valid 404 1m;
            proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
            proxy_pass http://127.0.0.1:8080;
        }
    }
}
```

## 14.8 Upstream — load balancing strategies

```nginx
# round-robin (default)
upstream backend {
    server 10.0.0.10:80;
    server 10.0.0.11:80;
}

# least connections
upstream backend_least {
    least_conn;
    server 10.0.0.10:80;
    server 10.0.0.11:80;
}

# ip_hash (session affinity)
upstream backend_sticky {
    ip_hash;
    server 10.0.0.10:80;
    server 10.0.0.11:80;
}
```

## 14.9 Security Headers — strong defaults

```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.example.com;" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

## 14.10 Rate limiting — protect API

```nginx
# place in http {}
limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;

server {
    listen 80;
    server_name api.example.com;

    location / {
        limit_req zone=one burst=20 nodelay;
        proxy_pass http://127.0.0.1:8080;
    }
}
```

## 14.11 Logging — JSON access log example

```nginx
log_format json_combined escape=json '{'
    '"time_local":"$time_iso8601",'
    '"remote_addr":"$remote_addr",'
    '"request":"$request",'
    '"status":"$status",'
    '"body_bytes_sent":"$body_bytes_sent",'
    '"request_time":"$request_time",'
    '"upstream_time":"$upstream_response_time"'
    '}';

access_log /var/log/nginx/access.log json_combined;
```

## 14.12 Stream — TCP proxy (MySQL example)

```nginx
stream {
    upstream mysql_up {
        server 10.0.0.20:3306;
        server 10.0.0.21:3306;
    }

    server {
        listen 3306;
        proxy_pass mysql_up;
    }
}
```

## 14.13 Mail — SMTP proxy skeleton

```nginx
mail {
    server_name mail.example.com;
    auth_http localhost:9000/auth;
    proxy_pass_error_message off;

    smtp_capabilities "SIZE" "8BITMIME" "PIPELINING";
    starttls on;
}
```

---

# NOTES

- Replace domain names, IPs, and file paths to match your environment.
- For production, validate config `sudo nginx -t` and reload `sudo systemctl reload nginx`.
- Consider using `include` snippets (e.g., `/etc/nginx/snippets/ssl-params.conf`) for reuse.

---
