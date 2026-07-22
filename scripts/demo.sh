#!/usr/bin/env bash
#
# base-servers · 60-second money demo
#
# Tells the whole agent-delegation story end to end against a running stack:
#   register a human (Alice) and an AI agent (Planner) → give Alice `doc.edit`
#   → Alice delegates a scoped, time-boxed credential to Planner → the agent is
#   ALLOWED in scope, DENIED out of scope, DENIED beyond what Alice herself has
#   (never exceeds the granter) → Alice revokes → the agent is DENIED in seconds.
#
# The script asserts every outcome, so it doubles as an end-to-end smoke test:
# it exits non-zero if any beat misbehaves.
#
# Prereqs: the stack is up (see below) and `jq` + `curl` are installed.
#
#   export BS_SIGNING_KEK=$(head -c 32 /dev/urandom | base64)
#   export BS_SERVICE_CLIENT_SECRET=svc-$(head -c 12 /dev/urandom | base64 | tr -dc a-z0-9)
#   export BS_ROOT_TOKEN=$(head -c 24 /dev/urandom | base64)
#   docker compose -f deploy/docker-compose.yml up -d --build
#   ./scripts/demo.sh
#
# Note: the control plane is authenticated. This script drives the whole flow
# with the break-glass BS_ROOT_TOKEN (bootstrap). In a real deployment Alice
# would issue her delegation with her own OIDC bearer token, not the root token.

set -euo pipefail

API="${API:-http://localhost:8081}"
: "${BS_ROOT_TOKEN:?set BS_ROOT_TOKEN to the same value the stack was started with}"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  G=$'\033[32m'; R=$'\033[31m'; B=$'\033[1m'; D=$'\033[2m'; Z=$'\033[0m'
else
  G=""; R=""; B=""; D=""; Z=""
fi

fail() { echo "${R}✗ $*${Z}" >&2; exit 1; }

# call SERVICE/METHOD '<json>' -> prints response body (fails on HTTP error)
call() {
  local out code
  out=$(curl -sS -w $'\n%{http_code}' -X POST "$API/baseservers.v1.$1" \
        -H 'Content-Type: application/json' \
        -H "X-BS-Root-Token: $BS_ROOT_TOKEN" \
        -d "$2") || fail "curl failed calling $1"
  code=${out##*$'\n'}; out=${out%$'\n'*}
  [ "$code" = "200" ] || fail "$1 -> HTTP $code: $out"
  printf '%s' "$out"
}

# assert_delegated TOKEN ACTION EXPECT(true|false) LABEL
assert_delegated() {
  local got
  got=$(call DelegationService/CheckDelegated \
        "{\"token\":\"$1\",\"action\":\"$2\",\"resourceType\":\"doc\",\"resourceId\":\"doc:1\",\"orgId\":\"$ORG\"}" \
        | jq -r '.allowed // false')
  if [ "$got" != "$3" ]; then fail "CheckDelegated($2) = $got, expected $3"; fi
  if [ "$3" = "true" ]; then echo "   ${G}✓ allowed${Z}  $4"; else echo "   ${R}✗ denied${Z}   $4"; fi
}

echo "${B}base-servers · money demo${Z}  ($API)"
curl -fsS "$API/readyz" >/dev/null 2>&1 || fail "stack not ready at $API/readyz — bring it up first (see the header of this script)"

echo
echo "${B}1. Identities${Z}"
ALICE=$(call PrincipalService/CreatePrincipal \
  '{"type":"PRINCIPAL_TYPE_HUMAN","displayName":"Alice"}' | jq -r '.principal.id')
[ -n "$ALICE" ] && [ "$ALICE" != "null" ] || fail "could not create Alice"
echo "   human   Alice   = ${D}$ALICE${Z}"
PLANNER=$(call PrincipalService/CreatePrincipal \
  "{\"type\":\"PRINCIPAL_TYPE_AGENT\",\"displayName\":\"Planner\",\"ownerPrincipalId\":\"$ALICE\",\"purpose\":\"triage\"}" \
  | jq -r '.principal.id')
[ -n "$PLANNER" ] && [ "$PLANNER" != "null" ] || fail "could not create Planner"
echo "   agent   Planner = ${D}$PLANNER${Z}  (owned by Alice)"

echo
echo "${B}2. Org + who has what${Z}"
ORG=$(call OrgService/CreateOrganization '{"name":"Acme"}' | jq -r '.organization.id')
[ -n "$ORG" ] && [ "$ORG" != "null" ] || fail "could not create org"
call OrgService/AddMember "{\"principalId\":\"$ALICE\",\"orgId\":\"$ORG\"}" >/dev/null
call OrgService/AddMember "{\"principalId\":\"$PLANNER\",\"orgId\":\"$ORG\"}" >/dev/null
ROLE=$(call RoleService/CreateRole \
  "{\"orgId\":\"$ORG\",\"name\":\"editor\",\"permissions\":[\"doc.edit\"]}" | jq -r '.role.id')
call RoleService/AssignRole \
  "{\"principalId\":\"$ALICE\",\"roleId\":\"$ROLE\",\"scopeType\":\"org\",\"scopeId\":\"$ORG\"}" >/dev/null
echo "   Alice is granted the ${B}editor${Z} role → she has ${B}doc.edit${Z} (but not billing.view / admin.super)"

echo
echo "${B}3. Alice delegates a scoped, 15-min credential to Planner${Z}"
ISSUE=$(call DelegationService/Issue \
  "{\"agentId\":\"$PLANNER\",\"delegatorId\":\"$ALICE\",\"orgId\":\"$ORG\",\"scope\":[\"doc.edit\"],\"ttlSeconds\":900}")
TOKEN=$(printf '%s' "$ISSUE" | jq -r '.token')
DID=$(printf '%s' "$ISSUE" | jq -r '.delegationId')
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || fail "Issue returned no token"
echo "   delegation ${D}$DID${Z}  scope=[doc.edit] ttl=15m"

echo
echo "${B}4. What the agent can actually do${Z}"
assert_delegated "$TOKEN" doc.edit     true  "in scope, and Alice has it"
assert_delegated "$TOKEN" billing.view false "out of scope"

echo
echo "${B}5. It can never exceed the granter${Z}"
# A delegation whose scope INCLUDES an action Alice herself lacks (admin.super).
ISSUE2=$(call DelegationService/Issue \
  "{\"agentId\":\"$PLANNER\",\"delegatorId\":\"$ALICE\",\"orgId\":\"$ORG\",\"scope\":[\"doc.edit\",\"admin.super\"],\"ttlSeconds\":900}")
TOKEN2=$(printf '%s' "$ISSUE2" | jq -r '.token')
assert_delegated "$TOKEN2" admin.super false "in scope, but Alice doesn't have it → still denied"

echo
echo "${B}6. Kill-switch${Z}"
call DelegationService/Revoke "{\"delegationId\":\"$DID\"}" >/dev/null
echo "   Alice revoked the delegation..."
assert_delegated "$TOKEN" doc.edit false "revoked → denied in seconds"

echo
echo "${G}${B}✓ money demo passed${Z} — scoped · time-boxed · revocable · attributable · never exceeds the granter"
