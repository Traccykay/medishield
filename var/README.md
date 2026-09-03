# Runtime forensic anchors

`audit-chain-anchors.jsonl` is created by `scripts/anchor-audit-chain.php`.
It is append-only runtime evidence and is ignored by Git. Keep this directory
outside the `public/` web root and, for rollback detection, place it on storage
administered independently from the application database and protect its
separate key outside the application host.
