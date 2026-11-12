# AgenticWF-auth-logto

The **Logto** provider of AgenticWF's identity and access layer: the provider package that plugs
Logto OSS into the auth service, and the container that runs Logto, PostgreSQL and authsvc. The
provider-neutral auth service (authsvc, the `agenticwf` CLI, the route policy, the architecture
docs) is in [AgenticWF-auth](https://github.com/InnovateAILab/AgenticWF-auth); the Keycloak
alternative in [AgenticWF-auth-keycloak](https://github.com/InnovateAILab/AgenticWf-auth-keycloak).

```
CLI / scripts  ── Bearer ──┐
Browser chat   ── cookie ──┼─HTTPS─► Caddy (host) ─► authsvc /verify ─► REST / Agent API
Status / SSE   ── cookie ──┘              │                │ Logto JWT / session
                                          ▼                ▼
                              Logto OSS ◄── INDIGO IAM / CERN SSO / Google / …
         [ AlmaLinux 9 container: Logto + PostgreSQL + authsvc, under supervisord ]
```

What is Logto-specific:

| | |
|---|---|
| Layout | Logto OSS owns `/` of its hostname; on a single hostname the application lives under `/app` |
| Setup | applications, API resource and roles created in the Logto console ([docs/deployment.md §4](docs/deployment.md)) |
| API permissions (`scopes` in the policy) | Logto API resource permissions (`scope`); tokens are requested with the API `resource` |
| Personal access tokens | Logto's own, exchanged for access tokens by the CLI (token exchange) |
| Groups (`/auth/groups`, `AuthContext.organizations`) | Logto organizations; admins hold the organization role `admin` |
| Who the user is | Logto tokens carry no name: authsvc looks it up through the Management API |
| CLI `AGENTICWF_AUTH_URL` | the Logto endpoint (or its issuer `<endpoint>/oidc`), plus `AGENTICWF_RESOURCE`; both published at `/auth/config` |

Build the image, with a checkout of AgenticWF-auth next to this one:

```bash
docker build --network=host --build-context agenticwf-auth=../AgenticWF-auth \
  -f container/Dockerfile -t agenticwf-auth-logto .
```

| Path | Content |
|---|---|
| [provider/](provider) | Package `agenticwf-auth-logto` (module `agenticwf_auth_logto`): Logto settings, claims mapping, OIDC endpoints, Management API client; `uvicorn --factory agenticwf_auth_logto:create_app` |
| [container/](container) | AlmaLinux 9 Dockerfile, supervisord config, scripts, env example |
| [deploy/caddy/Caddyfile](deploy/caddy/Caddyfile) | Main `/etc/caddy/Caddyfile` for every layout (`import Caddyfile.d/*.caddyfile`) |
| [deploy/caddy/sites/](deploy/caddy/sites) | Site layouts; install one into `/etc/caddy/Caddyfile.d/`: `agenticwf-single-host.caddyfile` (one hostname, port 443 only) or `agenticwf-multi-host.caddyfile` (separate hostnames); optional `agenticwf-admin-console.caddyfile` exposes the Logto admin console on `:8443` for development (single-host only) |
| [docs/deployment.md](docs/deployment.md) | Build, run, Caddy and Logto setup, operations |
| [.github/workflows/build-container.yml](.github/workflows/build-container.yml) | Tests the provider, builds and pushes the image on every new tag |

Development: `pip install -e ../AgenticWF-auth/authsvc -e 'provider[test]' && (cd provider && pytest -q)`.
