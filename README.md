# RDS Auth Proxy

An early, deliberately small local connector for Amazon RDS and Aurora. It listens on a loopback TCP address and forwards each connection to the database endpoint without altering its database protocol. A companion command generates short-lived IAM database authentication tokens with the normal AWS credential chain.

> [!IMPORTANT]
> This is not yet a drop-in equivalent of Cloud SQL Auth Proxy. It does **not** authenticate the database protocol, inject a password, or terminate TLS. Supply the generated token to your PostgreSQL or MySQL client as its password and enable TLS in that client. The proxy's job in this first milestone is simple local addressing, token generation, and container health checks.

## Build and run

```sh
go build -o rds-auth-proxy ./cmd/rds-auth-proxy
./rds-auth-proxy proxy \
  --endpoint my-cluster.cluster-abc.us-east-1.rds.amazonaws.com:5432 \
  --listen 127.0.0.1:5432
```

Generate a token using credentials from environment variables, shared configuration, web identity (EKS IRSA), or another AWS SDK credential provider:

```sh
export PGPASSWORD="$(./rds-auth-proxy token \
  --endpoint my-cluster.cluster-abc.us-east-1.rds.amazonaws.com:5432 \
  --region us-east-1 --user app)"
psql 'host=127.0.0.1 port=5432 user=app dbname=app sslmode=require'
```

The local leg is plaintext and therefore listens on loopback by default. `/healthz` is served on `127.0.0.1:9090`; pass an empty `--health-address` to disable it. IAM database authentication must be enabled on the database, and the AWS identity needs `rds-db:connect` for the database user.

## Direction

The transport core is intentionally database-agnostic and suitable for a future EKS sidecar. Planned milestones are:

1. PostgreSQL and MySQL protocol adapters that can inject refreshed IAM tokens.
2. Structured readiness that checks endpoint reachability, metrics, and graceful connection draining.
3. A Kubernetes mutating admission webhook that injects the proxy sidecar, uses workload identity, and defaults to a non-root security context.
4. Endpoint discovery and failover-aware Aurora cluster connections.

## Security model

* Database TLS is end-to-end and must be enabled in the client. Because the client connects to `localhost`, use the RDS CA bundle and appropriate client options if host-name verification is required.
* The listener defaults to loopback to avoid exposing connections to other hosts.
* Tokens are printed only on explicit request and are never written by the proxy or included in logs.
* The proxy does not make a private RDS endpoint reachable by itself. Run it somewhere with VPC network connectivity, such as an EKS pod in the VPC.
