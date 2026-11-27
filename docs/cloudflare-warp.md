# Optional Cloudflare Access for Infrastructure (WARP)

This guide is kept on `feat/cloudflare-ssh-certificates`. The production browser
terminal does not use this integration. Shared SSH certificate authentication
and certificate username aliases are maintained on `main` because the browser
terminal needs them too. There is no separate WARP-specific authentication code.

## Configure

1. Generate or retrieve the account's **Gateway SSH CA** through Cloudflare's
   `/access/gateway_ca` endpoint. The per-application browser SSH CA is different
   and cannot replace the Gateway CA for Infrastructure access.
2. Add the Gateway CA public key to the gateway's `trusted_user_ca_keys` file.
   Keep the browser application's CA too if both connection methods are wanted.
3. Create a Cloudflare Tunnel network route for the gateway's IP, then an
   Infrastructure target for that IP and virtual network. Scope network policies
   so the route exposes only the intended gateway SSH port.
4. Create an Infrastructure Access application targeting that hostname and port.
   Restrict its policy to the intended identity/provider and explicit gateway
   usernames. Disable automatic email-alias usernames unless deliberately needed.
5. Enroll the client in Cloudflare One Client in Traffic and DNS mode. Enable
   the Gateway TCP proxy and ensure split-tunnel settings include the target IP.
6. Connect with a normal SSH client using the explicitly permitted username.
   Cloudflare issues a short-lived certificate for that requested SSH username.

The canonical gateway user must already exist and be enabled. Downstream target
grants, role, TOTP, and session limits remain enforced. Routed `USER+TARGET`
logins require that exact login name in both the Cloudflare policy and certificate
principal. Do not use a blanket principal-to-user mapping.

Cloudflare's SSH proxy presents its own host identity. Direct SSH and WARP SSH
can therefore present different keys for the same hostname. Independently verify
both public keys before enrolling both in managed client `known_hosts` files.
Keep strict host-key checking enabled.

## Remove without affecting browser SSH

Remove the Infrastructure application, target, its network route and scoped
network rule. Remove Gateway CA trust from the gateway, retaining the browser
application's CA and any certificate-only username aliases it needs. Restart
the gateway from an independent or detached management session. Leave the
published browser SSH hostname, tunnel ingress and browser Access policy intact.
The deprecated `warp-routing` configuration flag is ignored by current
cloudflared; active network routes determine private network reachability.

References:

- [Cloudflare Access for Infrastructure SSH](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/use-cases/ssh/ssh-infrastructure-access/)
- [Cloudflare browser terminal](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/non-http/browser-rendering/)
