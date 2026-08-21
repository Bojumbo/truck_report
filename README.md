# Trucks - deployment

## Before deployment

1. Create a private GitHub repository and push this directory.
2. In Portainer, create a **Stack** from the repository and select `compose.yaml`.
3. Add the variables from `.env.example` in the stack's environment section. Never put `.env` in Git.
4. In Portainer create the external Docker network `trucks_tunnel`, then attach both this stack and the separate Cloudflare Tunnel container to it. Point the tunnel public hostname `trucks.bojumbohost.pp.ua` to `http://app:3000`. The application is also bound to the server loopback at port `8990` (`127.0.0.1:8990`) for local diagnostics.
5. Deploy and verify `https://trucks.bojumbohost.pp.ua/health` returns `{ "ok": true }`.

The application creates the first administrator at its initial boot using `ADMIN_EMAIL` and `ADMIN_PASSWORD`. Change the password by updating `ADMIN_PASSWORD` and redeploying only before the first boot; subsequently use the admin driver-management endpoint/UI.

## Security

- PostgreSQL is not published outside Docker.
- The application port binds only to loopback; Cloudflare Tunnel is the public ingress.
- Generate distinct random values for `POSTGRES_PASSWORD` and `JWT_SECRET`.
- Take regular backups of the `trucks_postgres` Docker volume.
