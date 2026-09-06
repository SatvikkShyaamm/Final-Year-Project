# infra/l-pep

Reserved for Module 4 (Dynamic ACL Management).

This will hold the Lightweight Policy Enforcement Point (L-PEP) component
described in the base paper — the process that executes `ipset add` /
`ipset del` against a pre-configured allow-list (mirroring the paper's
`ztsaacm_allowed` / `ztsaacm_allowed_v6` sets) in response to tasks placed
on the Redis queue by the backend.

Left empty in Module 1: there is no ACL concept, session, or Redis task
producer yet for an enforcement process to consume from.
