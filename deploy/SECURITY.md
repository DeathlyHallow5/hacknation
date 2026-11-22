# Deployment and recovery

Use compose.production.yaml as a standalone Compose project. This configuration runs the API in inventory-only mode (ASI_MAX_RUNS=0). Only the TLS proxy publishes a port. The core and database have internal networks. Provide release images by repository and SHA-256 digest, an operator-controlled public hostname, and a matching certificate and private key. Mount secrets from files outside the checkout. The database URL must contain the same password as the database secret, URL-encoded when necessary. Validate with docker compose -f compose.production.yaml config --quiet. The built images must include the current security changes.

For a local lab worker, approve explicit IPv4 CIDRs and numeric ports with ASI_ALLOWED_CIDRS and ASI_ALLOWED_PORTS. ASI_EXCLUDED_CIDRS overrides approvals. Profiles using top-port presets require conversion to explicit approved ports. ASI_GLOBAL_PPS is shared across configured worker slots within one instance; this is a scanner argument ceiling, not packet-level enforcement. Create deploy/control/STOP on the host to interrupt running scanner processes and refuse further launches. Keep it present until an administrator clears the incident. If an immediate network cutoff is required, isolate the worker at the network boundary.

## Backup and key rotation

1. Pause workers, stop writes, record the application image digest, migration version and current key version. Create a PostgreSQL custom-format dump and encrypt the backup at the storage layer. Keep the matching versioned ASI_DATA_KEY in separate restricted storage.
2. Restore into an isolated empty database. Verify migration versions, row counts and decryption of representative evidence without displaying plaintext. Exercise login and viewer redaction.
3. Rotate first on that restored copy. Inventory every column containing pgcrypto ciphertext (including evidence, historical annotations, diff values and artifacts). Re-encrypt with the replacement key in a transaction using bound parameters. Verify row counts and decryption with the new key before committing. Use restricted tooling without SQL parameter logging.
4. During a write outage repeat the validated transaction on the deployment, update the mounted secret and restart all instances together. A file change alone cannot rotate existing ciphertext. On failure restore the previous database snapshot and matching key version together.
5. Enforce backup expiry and preserve older keys until the last backup requiring them expires. Historical backups and old database rows may contain credentials collected before the redaction change. Rotate exposed credentials independently.

## Outstanding acceptance evidence

A production release with active scanning still requires packet-level egress tests for approved domains, DNS rebinding, redirects, exclusions and overlapping runs; per-subnet token budgets and observation of emergency stop latency. Validate the deployed TLS endpoint, backup restoration and data-key rotation with the operator's release images and certificate. Review access to shared records versus user-owned objects and verify that legacy evidence, user-entered notes, titles, redirects, imported data, backups and exports comply with the deployment's retention policy.
