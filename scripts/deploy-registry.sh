#!/usr/bin/env bash
#
# Deploy a Nido-owned `stellar-registry` INSTANCE and register the core
# contract names (factory / verifier / zk-recovery) into it (plan A3).
#
# WHY
#   On mainnet there is no shared registry we control. The factory both reads
#   `verifier`/`zk-recovery` FROM a registry (`Self::resolve`) and is published
#   INTO one as `factory`. Rather than trust an external registry, we deploy our
#   own instance whose owner key lives under the multisig. Once the factory
#   PINS `verifier`/`zk-recovery` (plan B2, `set_registry_pins`), the registry is
#   off the account-creation critical path entirely: a repoint can neither
#   reroute nor block new accounts. The registry then matters only for
#   off-chain discovery (`fetch_contract_id("factory")`) and unpinned names.
#
# WHAT (the registry contract is EXTERNAL — we do not build it)
#   The registry is AhaLabs' smart-deploy contract, referenced elsewhere only by
#   address. This script FETCHES the exact on-chain wasm of a known-good registry
#   (default: the testnet "unverified" registry) via `stellar contract fetch`,
#   records its sha256, and deploys a FRESH instance of that same bytecode with
#   our own owner. Recording the hash lets an auditor confirm our instance runs
#   byte-identical code to the reference registry (provenance for SUPPLY_CHAIN.md
#   / AUDIT_SCOPE.md — the registry becomes a trusted mainnet-critical contract).
#
# IMPORTANT — CONFIRM ON TESTNET FIRST
#   The registry's constructor (owner/init) and its "register a name" entry point
#   are properties of the EXTERNAL contract, not of nido. This script parameterises
#   both: pass constructor args after `--`, and override the register verb with
#   $REGISTER_VERB if the reference registry uses something other than
#   `update_contract_address` for a NEW name. REHEARSE THE FULL FLOW ON TESTNET
#   (deploy → register → `factory.resolve`) before running it against mainnet.
#
# Usage:
#   ./scripts/deploy-registry.sh <keys-alias> [network] [-- <ctor args...>]
#
#   <alias>    Required. `stellar keys` identity that deploys + owns the registry.
#              On MAINNET this MUST resolve to (or hand ownership to) the multisig.
#   [network]  Optional, default "testnet". Sets --network AND STELLAR_NETWORK.
#   -- args    Optional. Constructor args forwarded verbatim to
#              `stellar contract deploy ... -- <args>` (e.g. `-- --owner C...`).
#
# Env overrides:
#   SOURCE_REGISTRY  Registry whose wasm we copy (default: testnet unverified
#                    CDBL7MNO...). Its wasm is fetched over $SOURCE_NETWORK.
#   SOURCE_NETWORK   Network to fetch SOURCE_REGISTRY's wasm from (default: testnet).
#   OWNER            Convenience: if set and no `-- <ctor args>` are given, the
#                    script passes `-- --owner "$OWNER"`. Skipped when explicit
#                    ctor args are supplied.
#   FACTORY          Address to register under `factory`      (skipped if unset).
#   VERIFIER         Address to register under `verifier`     (skipped if unset).
#   ZK_RECOVERY      Address to register under `zk-recovery`  (skipped if unset).
#   REGISTER_VERB    Registry fn used to bind a name→address (default
#                    `update_contract_address`, args `--contract_name`/`--new_address`;
#                    the verb DEPLOYED.md documents for repoints).
#   OUT_DIR          Where to write the fetched wasm (default target/registry).
#   DRY_RUN          If set, print the commands instead of running deploy/invoke.
#
# Prereqs: `stellar` CLI (>= 26). No scaffold `stellar registry` plugin needed —
# this uses only base `contract fetch`/`deploy`/`invoke`.

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 <keys-alias> [network] [-- <ctor args...>]" >&2
    echo "  see 'stellar keys ls' for available aliases" >&2
    exit 2
fi

ALIAS="$1"; shift
NETWORK="testnet"
if [ $# -gt 0 ] && [ "$1" != "--" ]; then NETWORK="$1"; shift; fi
if [ $# -gt 0 ] && [ "$1" = "--" ]; then shift; fi
CTOR_ARGS=("$@")   # anything after `--`

export STELLAR_NETWORK="$NETWORK"

SOURCE_REGISTRY="${SOURCE_REGISTRY:-CDBL7MNO7UI5OAAIC67UIWKQ4P3S6RVQSFCQXUHUW6TOFCXSYRPNHY4S}"
SOURCE_NETWORK="${SOURCE_NETWORK:-testnet}"
REGISTER_VERB="${REGISTER_VERB:-update_contract_address}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/target/registry}"
WASM="$OUT_DIR/stellar_registry.wasm"

# If the caller gave no explicit constructor args but set $OWNER, pass it.
if [ "${#CTOR_ARGS[@]}" -eq 0 ] && [ -n "${OWNER:-}" ]; then
    CTOR_ARGS=(--owner "$OWNER")
fi

note()  { printf "\n\033[1m▸ %s\033[0m\n" "$*"; }
ok()    { printf "  \033[32m✓\033[0m %s\n" "$*"; }
skip()  { printf "  \033[90m·\033[0m %s\n" "$*"; }
warn()  { printf "  \033[33m!\033[0m %s\n" "$*" >&2; }
die()   { printf "\033[31m✗ %s\033[0m\n" "$*" >&2; exit 1; }
run()   { if [ -n "${DRY_RUN:-}" ]; then printf "  [dry-run] %s\n" "$*"; else eval "$*"; fi; }

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
    else die "need sha256sum or shasum"; fi
}

command -v stellar >/dev/null 2>&1 || die "stellar CLI not found on PATH"

# Owner guard: registry ownership must never silently default to the deployer key
# on a real network. Fail CLOSED -- only the known testnet-family networks skip the
# explicit-owner requirement; anything else (mainnet, public, OR a custom alias like
# `pubnet`/`nido-mainnet`) demands an explicit owner, so keying on the literal string
# "mainnet"/"public" can't be evaded by a differently-named network. (Sibling
# deploy-zk-recovery.mjs keys its guard on the network passphrase for the same reason.)
case "$NETWORK" in
    testnet | local | standalone | futurenet) : ;;
    *)
        if [ "${#CTOR_ARGS[@]}" -eq 0 ]; then
            die "network '$NETWORK' is not a known testnet: registry owner must be explicit — pass '-- --owner <MULTISIG>' or set OWNER (a multisig C-address, not the deployer)"
        fi
        warn "network '$NETWORK': confirm the owner arg below is the MULTISIG, and that you rehearsed this on testnet."
        ;;
esac

note "Fetch reference registry wasm ($SOURCE_REGISTRY @ $SOURCE_NETWORK)"
mkdir -p "$OUT_DIR"
stellar contract fetch --id "$SOURCE_REGISTRY" --network "$SOURCE_NETWORK" --out-file "$WASM" \
    || die "could not fetch reference registry wasm (network/id?)"
WASM_HASH="$(sha256_of "$WASM")"
ok "wasm $WASM"
ok "sha256 $WASM_HASH   ← record in DEPLOYED.md (registry provenance)"

note "Deploy fresh registry instance on $NETWORK"
if [ "${#CTOR_ARGS[@]}" -gt 0 ]; then
    ok "constructor args: ${CTOR_ARGS[*]}"
    NEW_REGISTRY="$(run "stellar contract deploy --wasm '$WASM' --source-account '$ALIAS' --network '$NETWORK' -- ${CTOR_ARGS[*]}")"
else
    warn "no constructor args given (deploying with none — confirm the registry needs none on testnet first)"
    NEW_REGISTRY="$(run "stellar contract deploy --wasm '$WASM' --source-account '$ALIAS' --network '$NETWORK'")"
fi
[ -n "${DRY_RUN:-}" ] && NEW_REGISTRY="C_DRYRUN_REGISTRY_ID"
ok "registry deployed: $NEW_REGISTRY"

register() {
    local name="$1" addr="$2"
    [ -z "$addr" ] && { skip "$name: no address provided (set \$$3) — skipping"; return 0; }
    note "Register '$name' → $addr"
    if run "stellar contract invoke --id '$NEW_REGISTRY' --source-account '$ALIAS' --network '$NETWORK' \
        -- $REGISTER_VERB --contract_name '$name' --new_address '$addr'"; then
        ok "$name registered"
    else
        die "failed to register '$name' (verb '$REGISTER_VERB' wrong? confirm on testnet, override with REGISTER_VERB)"
    fi
}

register "factory"     "${FACTORY:-}"     FACTORY
register "verifier"    "${VERIFIER:-}"    VERIFIER
register "zk-recovery" "${ZK_RECOVERY:-}" ZK_RECOVERY

note "Done"
cat <<EOF
  Registry id   : $NEW_REGISTRY
  Registry wasm : $WASM_HASH

  Next:
    1. Record the registry id + wasm hash in DEPLOYED.md, and list the registry
       in AUDIT_SCOPE.md / SUPPLY_CHAIN.md as a trusted mainnet-critical contract.
    2. Set the factory REGISTRY constant (contracts/factory/src/contract.rs) and
       the SDK/frontend fallbacks (packages/passkey-sdk/src/registry.ts,
       packages/frontend/src/lib/policyChainFetch.ts) to this registry id; rebuild.
    3. Pin the factory (plan B2): factory.set_registry_pins(<verifier>, <zk-recovery>).
       After pinning, the registry is off the account-creation critical path.
EOF
