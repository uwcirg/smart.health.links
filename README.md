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
TEST=1 deno test --allow-env --allow-read=".","./db","./tests" --allow-write="./db","./tests" --allow-net tests/api.test.ts
```

# Configuration

Server configuration is set via environment variables (see `default.server.env` for the full list). For production-like deployments, set `CORS_ALLOWED_ORIGINS` to a comma-separated list of allowed origins to restrict cross-origin requests, eg:
```
CORS_ALLOWED_ORIGINS=https://app.example.org,https://admin.example.org
```
Leave it unset for local development to reflect any origin.

# Build in Docker

```sh
docker build -t vaxx.link .
docker run --rm -it -p 8000:8000 vaxx.link
```
