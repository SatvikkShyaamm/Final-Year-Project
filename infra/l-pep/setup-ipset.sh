#!/usr/bin/env bash
# Module 4 — create the kernel allow-list sets and the iptables rules that
# gate the protected resource. Run ONCE on the L-PEP host (Linux, root/CAP_NET_ADMIN).
#
# After this, `ACL_ENFORCEMENT_BACKEND=ipset python -m app.lpep` (from backend/)
# will `ipset add`/`del` client IPs into ztsaacm_allowed as sessions come and go.
set -euo pipefail

V4_SET="${ACL_IPSET_V4:-ztsaacm_allowed}"
V6_SET="${ACL_IPSET_V6:-ztsaacm_allowed_v6}"
# Port(s) of the protected resource to gate. Adjust to your demo target.
PROTECTED_PORT="${PROTECTED_PORT:-8080}"

echo "==> Creating ipset sets (idempotent)"
ipset create "$V4_SET" hash:ip family inet  timeout 0 -exist
ipset create "$V6_SET" hash:ip family inet6 timeout 0 -exist

echo "==> iptables: allow members of $V4_SET to reach tcp/$PROTECTED_PORT, drop the rest"
iptables  -C INPUT -p tcp --dport "$PROTECTED_PORT" -m set --match-set "$V4_SET" src -j ACCEPT 2>/dev/null \
  || iptables  -I INPUT -p tcp --dport "$PROTECTED_PORT" -m set --match-set "$V4_SET" src -j ACCEPT
iptables  -C INPUT -p tcp --dport "$PROTECTED_PORT" -j DROP 2>/dev/null \
  || iptables  -A INPUT -p tcp --dport "$PROTECTED_PORT" -j DROP

ip6tables -C INPUT -p tcp --dport "$PROTECTED_PORT" -m set --match-set "$V6_SET" src -j ACCEPT 2>/dev/null \
  || ip6tables -I INPUT -p tcp --dport "$PROTECTED_PORT" -m set --match-set "$V6_SET" src -j ACCEPT
ip6tables -C INPUT -p tcp --dport "$PROTECTED_PORT" -j DROP 2>/dev/null \
  || ip6tables -A INPUT -p tcp --dport "$PROTECTED_PORT" -j DROP

echo "Done. Current sets:"
ipset list -n
