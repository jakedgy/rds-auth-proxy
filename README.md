# RDS Auth Proxy

A small PostgreSQL connector for Amazon RDS and Aurora. It uses the proxy
process's ambient AWS identity to generate a fresh IAM database authentication
token whenever a client opens a connection. Applications therefore do not need
AWS credentials, a database password, or a separate token-generation step.

## Build and run

```sh
go build -o rds-auth-proxy ./cmd/rds-auth-proxy
./rds-auth-proxy proxy \
  --endpoint my-cluster.cluster-abc.us-east-1.rds.amazonaws.com:5432 \
  --region us-east-1 \
  --listen 127.0.0.1:5432 \
  --tls-negotiation direct \
  --root-ca global-bundle.pem
```

The proxy loads credentials using the normal AWS SDK credential chain, including
environment variables, shared configuration, web identity (EKS IRSA), and
container credentials. The PostgreSQL startup packet supplies the database user,
so no user is configured on the proxy. Connect `psql` directly, without setting
`PGPASSWORD`:

```sh
psql 'host=127.0.0.1 port=5432 user=app dbname=app sslmode=disable'
```

The local connection is deliberately plaintext so that the proxy can handle the
PostgreSQL authentication exchange. It rejects client SSL and GSS encryption
requests, establishes a separate verified TLS 1.2+ connection to RDS, and sends
the newly generated token in response to RDS's cleartext-password authentication
request. The token and application traffic are protected on the network-facing
connection and tokens are never sent to or requested from the local client.

`--root-ca` adds a PEM CA bundle to the system trust store. Use the current AWS
RDS CA bundle when it is not already trusted by the host. Certificate verification
always uses the RDS endpoint hostname; it is never disabled.

The default `--tls-negotiation postgres` uses PostgreSQL's traditional SSL
request. Set it to `direct` for Aurora configurations whose gateway requires a
TLS ClientHello (and SNI) as the first upstream packet, including Aurora
PostgreSQL express configurations. This option affects only the upstream leg.

`/healthz` is served on `127.0.0.1:9090`; pass an empty `--health-address` to
disable it. IAM database authentication must be enabled on the database, the
PostgreSQL user must be configured for IAM authentication, and the proxy's AWS
identity needs `rds-db:connect` for that user.

## Legacy token command

The standalone command remains available for diagnostics, although normal psql
usage no longer needs it:

```sh
./rds-auth-proxy token \
  --endpoint my-cluster.cluster-abc.us-east-1.rds.amazonaws.com:5432 \
  --region us-east-1 --user app
```

## Security model

* The database-facing connection always uses verified TLS 1.2 or newer.
* The local listener defaults to loopback. Keep it on a trusted network namespace;
  any local process able to connect can request access as an IAM-enabled database
  user authorized for the proxy's AWS identity.
* A token is generated per connection and is neither logged nor exposed to the
  PostgreSQL client.
* The proxy does not make a private RDS endpoint reachable by itself. Run it with
  VPC network connectivity, such as an EKS sidecar in the VPC.

## Current scope

This milestone supports PostgreSQL protocol version 3 and the cleartext-password
authentication exchange used by RDS IAM authentication. MySQL, client-side TLS,
PostgreSQL channel binding, endpoint discovery, and failover-aware cluster
connections are not yet supported.
