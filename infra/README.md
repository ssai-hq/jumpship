# Infrastructure

OpenTofu roots and reusable modules are separated by bootstrap, organization, control-plane, signer, Mothership, cell, Vercel, observability, recovery, cost, and local-development authority. Root modules pin providers and state backends; reusable modules do not own environment credentials.

Plans and tests may use synthetic identifiers only. Secrets, state files, customer facts, and live account exports are never committed.
