# Mounted private-source drift tests

## Accepted source

```text
./scripts/capabilities/check-private-source --source <mounted-absolute-living-source>
private source check: PASS source_sha256=89008f738028f4f0e6721c268682e02b4a79119c7a77c6c2168aaf3becfce49d anchors=253
exit: 0
```

The placeholder above redacts the user-specific private path; the command used the exact frozen living-source file named by the packet.

## Changed-byte/anchor rejection

A temporary copy changed one byte-bearing numbered occurrence and was checked with a candidate path outside the repository:

```text
private source check: FAIL source_hash_equal=false missing=0 added=0 changed=1
changed anchors: ['numbered-list:1:tiered-access-manifest-every-grant-jumpship-requests-is']
review candidate written: /private/tmp/p00-source-review-candidate.yaml
exit: 1 (expected rejection)
```

Accepted manifest SHA-256 before and after: `f40fa3e49a9bff54b5d0db5904d0695ff333b77e06e382bbfa226a859b56f72b`.

The candidate retained 253 anchors but carried changed source and source-plan hashes, proving it was a review artifact rather than an accepted mutation.

## Accepted-file overwrite denial

An attempted repository-local candidate path targeting `contracts/capabilities/mvp.yaml` was rejected with exit 2. Registry SHA-256 before and after remained `2ee442183304a538b47ee3da7e76d587e3f792538ff46eec2187ebec7a5a61bc`.
