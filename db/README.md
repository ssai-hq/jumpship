# Database assets

Database migrations, generated query sources, grants, and synthetic fixtures are separated by `control`, `cell`, and selected-target custody boundaries. A migration is append-only after acceptance, runs under its dedicated migration role, and ships with forward, compatibility, and rollback evidence.

No production data, connection string, credential, or customer-derived fixture belongs here.
