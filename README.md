# SHLinks Demo Server

* Creates new SHLinks and adds files to them
* Authorizes access
* Shares files with authorized clients'

# Run
```
deno run --allow-env="PORT","PUBLIC_URL","EMBEDDED_LENGTH_MAX" --allow-read=".","./db" --allow-write="./db" --allow-net --watch server.ts
```

# Test

```sh
deno test --allow-env --allow-read=".","./db" --allow-write="./db" --allow-net
```

# Configuration

POST requests (including `/authcheck`) are rate limited per client IP. Defaults to 30 requests per 60 second window; override with `RATE_LIMIT_MAX_REQUESTS` and `RATE_LIMIT_WINDOW_MS`. The server trusts `X-Forwarded-For` from its reverse proxy to identify clients, so it must always run behind one (see `k8s.yml` / `docker-compose.traefik-ingress.yaml`).

# Build in Docker

```sh
docker build -t vaxx.link .
docker run --rm -it -p 8000:8000 vaxx.link
```
