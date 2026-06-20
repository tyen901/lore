# Deploy public object-store reads for Lore payloads

This guide configures Lore so developer writes still go through `loreserver`, while read-only clients fetch immutable payload bytes directly from a public object store.

Target shape:

```text
developer write path:
  lore client -> loreserver -> Cloudflare R2 PutObject
                         \-> AWS DynamoDB metadata/state/locks

read-only path:
  lore client -> loreserver for repository, revision, and metadata
  lore client -> public R2 custom-domain URL for payload objects
```

`loreserver` remains the authority for repositories, revision resolution, mutable state, metadata writes, locks, push validation, and immutable payload writes. It is not the normal byte relay for read-only payload downloads when public reads are enabled.

## Production services

Use this layout:

- VPS: `loreserver` Docker container.
- Payload object store: Cloudflare R2 public bucket with a custom domain.
- Metadata, mutable state, and locks: AWS DynamoDB tables in on-demand capacity mode.

Cloudflare documents public R2 access through custom domains and Cloudflare-managed `r2.dev` URLs; use the custom domain path for production. R2 does not charge egress bandwidth fees, but storage and operations are still billed. R2 S3-compatible clients use endpoint `https://<ACCOUNT_ID>.r2.cloudflarestorage.com` and region `auto`. DynamoDB on-demand capacity avoids provisioning throughput for this workload.

Relevant provider docs:

- Cloudflare R2 public buckets: <https://developers.cloudflare.com/r2/buckets/public-buckets/>
- Cloudflare R2 pricing: <https://www.cloudflare.com/products/r2/>
- Cloudflare R2 S3 API compatibility: <https://developers.cloudflare.com/r2/api/s3/api/>
- AWS DynamoDB on-demand capacity: <https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/on-demand-capacity-mode.html>

## Object URL model

Payload object keys are deterministic and content-addressed:

```text
object key = lowercase hex content hash
public URL = {public_read_base_url}/{lowercase_hex_content_hash}
```

Example:

```text
https://objects.example.com/8f14e45fceea167a5a36dedd4bea2543...
```

Do not put repository IDs, branch names, filenames, or revision names into public payload keys.

## loreserver config

Configure the AWS immutable store for R2 writes and public HTTP reads:

```toml
[immutable_store]
mode = "aws"

[mutable_store]
mode = "aws"

[lock_store]
mode = "aws"

[plugins.aws.immutable_store]
s3_bucket = "lore-public-payloads"
s3_endpoint_url = "https://<ACCOUNT_ID>.r2.cloudflarestorage.com"
s3_region = "auto"
s3_force_path_style = true

public_read_enabled = true
public_read_base_url = "https://objects.example.com"

dynamodb_fragments_table = "lore-fragments"
dynamodb_metadata_table = "lore-fragment-metadata"
dynamodb_region = "ap-southeast-2"

[plugins.aws.mutable_store]
dynamodb_table = "lore-mutable"
dynamodb_region = "ap-southeast-2"

[plugins.aws.lock_store]
dynamodb_table = "lore-locks"
dynamodb_region = "ap-southeast-2"
```

`public_read_base_url` is normalized by the server by removing trailing slashes. It must be present when `public_read_enabled = true`.

## Client behavior

Clients discover public immutable-payload read capability from `loreserver`; normal users do not enter the public bucket URL in clone or update commands.

When public reads are enabled, missing immutable payload reads use this order:

1. Local immutable store/cache.
2. Public HTTP GET from `{public_read_base_url}/{hash_hex}`.
3. Fail.

There is no silent fallback to `loreserver` for payload bytes in public-read mode. The public bucket is intentionally untrusted; every downloaded payload is verified against the expected Lore content hash before it is cached or used.

When `public_read_enabled = false`, the existing server-stream read path remains active.
