# ADR-007: Shared and Cell Compute

- Status: Accepted
- Date: 2026-07-17
- Owners: infrastructure owner, security/data owner
- Supersedes: None
- Superseded by: None

## Context and decision

Shared stateless services run on ECS Fargate. Stateful, disk-heavy, long-lived migration cells run on EC2 with EBS. Packer is the sole MVP AMI builder. Cell generations are replaced under signed lifecycle control rather than widened in place.

## Alternatives and rejection

EKS, Lambda data paths, and multi-node cell orchestration add control planes without solving MVP guarantees. Fargate is unsuitable for the cell's restore, disk, kill-resume, and long-running workload.

## Consequences, migration, and rollback

P09-P12 own IaC, images, IAM/network, lifecycle, and recovery checks. Measured shared-load cost, a genuinely multi-node cell, or a requalified safer builder may justify a superseding ADR.

## Traceability

- Capabilities: `MVP-CAP-AWS-CELL`, `MVP-CAP-ARCH-TRUST-DOMAINS`
- Acceptance: `JSMVP-R001`, later infrastructure/isolation rows
- Evidence: [`../architecture/system-boundaries.md`](../architecture/system-boundaries.md)
