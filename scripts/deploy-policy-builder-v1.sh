#!/usr/bin/env bash
#
# Tasks 4 & 4b of the Policy Builder v1 plan:
#   - Publish + deploy the multisig-policy under its canonical registry name
#   - Ensure the WebAuthn verifier is registered by name (publish + deploy
#     if not)
#   - Publish the factory wasm, deploy a FRESH admin-capable factory
#     (passing --admin via __constructor), and repoint the registry
#     'factory' name to it (a pre-admin factory can't self-upgrade)
#
# Idempotent: each step checks current state and skips work that's already done.
#
# Usage:
#   ./scripts/deploy-policy-builder-v1.sh <stellar-keys-alias> [network]
#
#   <alias>   Required. The `stellar keys` identity authorized to publish under
#             your registry namespace (see `stellar keys ls`).
#   [network] Optional, defaults to "testnet". Sets STELLAR_NETWORK for the
#             stellar-registry CLI (which doesn't accept --network directly).
#
# Prerequisites:
#   - `stellar` CLI (>= 26)
#   - `just` available on PATH
#   - The deployed factory's existing contract ID matches FACTORY_CONTRACT_ID
#     below; if you've redeployed elsewhere, edit the constant or pass
#     FACTORY_CONTRACT_ID as an env var.
#
# Environment overrides:
#   FACTORY_CONTRACT_ID  Existing deployed factory address (default = the
#                        testnet instance the frontend currently targets).
#   POLICY_VERSION       multisig-policy semantic version (default 0.1.0).
#   ACCOUNT_VERSION      smart-account wasm version to publish under
#                        unverified/smart-account (default 0.1.0). This is just
#                        the registry label; the factory deploys by sha256 of
#                        its embedded wasm, and this script asserts the
#                        published/installed bytes' hash matches that embedded
#                        wasm.
#   FACTORY_VERSION      factory wasm version to publish + deploy fresh from
#                        (default 0.4.0; the admin-capable factory).
#   REGISTRY_PREFIX      Prefix for unverified registry names (default
#                        "unverified/"). Set to "" to use the verified
#                        registry (requires curation rights).
#   SKIP_BUILD           If set, skip `just build-contracts`.
#
# Upgradability (issue #26): the factory, multisig-policy AND webauthn
# verifier now each carry an admin-gated upgrade() (admin set via
# __constructor(admin: Address) at deploy time). So this script passes
# `-- --admin <ADMIN_ADDR>` on every FRESH deploy below. ADMIN_ADDR
# defaults to the deploying alias's public key; override it with a
# multisig on mainnet (ideally behind an upgrade timelock).
#
# IMPORTANT: a constructor only runs at DEPLOY time, so an in-place
# `stellar registry upgrade` of a PRE-admin contract can never populate
# the admin slot — admin()/upgrade() would keep trapping. Migrating a
# pre-admin deployment therefore still means: deploy a FRESH contract
# (passing --admin) at a new address and repoint its registry name to it
# (the factory section below does exactly this). Once a contract carries
# an admin, subsequent code changes CAN use its own upgrade() in place.
#
# REGISTRY for testnet is CDBL7MNO7UI5OAAIC67UIWKQ4P3S6RVQSFCQXUHUW6TOFCXSYRPNHY4S
# (the unverified registry). See #25 / #26.

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 <stellar-keys-alias> [network]" >&2
    echo "  see 'stellar keys ls' for available aliases" >&2
    exit 1
fi

ALIAS="$1"
NETWORK="${2:-testnet}"
export STELLAR_NETWORK="$NETWORK"   # the CLI doesn't take --network; reads env

FACTORY_CONTRACT_ID="${FACTORY_CONTRACT_ID:-CDQDNOT4RWQKAIJIZYJE5HK7DMIVTYBJ4QXHIERNOZPPYMUNBT2JZ2SK}"
POLICY_VERSION="${POLICY_VERSION:-0.2.0}"
VERIFIER_VERSION="${VERIFIER_VERSION:-0.2.0}"
ACCOUNT_VERSION="${ACCOUNT_VERSION:-0.1.0}"
FACTORY_VERSION="${FACTORY_VERSION:-0.4.0}"
REGISTRY_PREFIX="${REGISTRY_PREFIX:-unverified/}"

# Canonical registry names (prefixed). These are what `factory.resolve(name)`
# looks up — but the contract calls `fetch_contract_id` with the BARE name
# (without prefix). The verified registry's `unverified` namespace then maps
# bare names to the unverified entries. If your CLI is configured for a
# specific named registry, this prefix lets us pass through without changing
# the factory source.
POLICY_NAME="${REGISTRY_PREFIX}multisig-policy"
VERIFIER_NAME="${REGISTRY_PREFIX}verifier"
ACCOUNT_NAME="${REGISTRY_PREFIX}smart-account"
FACTORY_NAME="${REGISTRY_PREFIX}factory"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
POLICY_WASM="$REPO_ROOT/target/wasm32v1-none/contract/nido_multisig_policy.wasm"
VERIFIER_WASM="$REPO_ROOT/target/wasm32v1-none/contract/nido_webauthn_verifier.wasm"
ACCOUNT_WASM="$REPO_ROOT/target/stellar/$NETWORK/smart_account_${ACCOUNT_VERSION//./_}.wasm"
FACTORY_WASM="$REPO_ROOT/target/wasm32v1-none/contract/nido_factory.wasm"

cd "$REPO_ROOT"

# --- helpers --------------------------------------------------------------

note()   { printf "\n\033[1m▸ %s\033[0m\n" "$*"; }
ok()     { printf "  \033[32m✓\033[0m %s\n" "$*"; }
skip()   { printf "  \033[90m·\033[0m %s\n" "$*"; }
warn()   { printf "  \033[33m!\033[0m %s\n" "$*" >&2; }
die()    { printf "\033[31m✗ %s\033[0m\n" "$*" >&2; exit 1; }

# Returns the contract ID for a registered name, empty string if not registered.
# Only reads stdout (stderr can contain unrelated C-addresses from error
# messages, which would false-positive a grep). Errors → empty.
fetch_contract_id() {
    local name="$1" out
    out="$(stellar registry fetch-contract-id "$name" --source-account "$ALIAS" 2>/dev/null)" \
        || return 0
    printf '%s' "$out" | grep -oE 'C[A-Z0-9]{55}' | head -1
}

# Print the lowercase hex sha256 of a file, using whichever tool is available
# (sha256sum on Linux, shasum -a 256 on macOS). Returns non-zero if neither
# tool exists so the caller can `die` with context.
sha256_of() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        return 1
    fi
}

# Returns the admin address of a factory contract, empty if the contract
# doesn't implement admin() or has no admin stored (i.e. it predates the
# admin constructor and traps on admin()). Reads stdout only; errors → empty.
factory_admin() {
    local id="$1" out
    out="$(stellar contract invoke --id "$id" --source-account "$ALIAS" \
        -- admin 2>/dev/null)" || return 0
    printf '%s' "$out" | grep -oE 'G[A-Z0-9]{55}|C[A-Z0-9]{55}' | head -1
}

# Returns the wasm hash for a published (name, version), empty if not published.
fetch_hash() {
    local name="$1" version="$2" out
    out="$(stellar registry fetch-hash "$name" --version "$version" --source-account "$ALIAS" 2>/dev/null)" \
        || return 0
    printf '%s' "$out" | grep -oE '[0-9a-f]{64}' | head -1
}

# --- preflight ------------------------------------------------------------

note "Preflight"

command -v stellar >/dev/null \
    || die "'stellar' CLI not found on PATH"
command -v just >/dev/null \
    || die "'just' not found on PATH (needed for build-contracts)"

if ! stellar keys ls 2>/dev/null | grep -qx "$ALIAS"; then
    die "'$ALIAS' is not a known stellar keys alias. Run 'stellar keys ls' to check."
fi
ok "Using stellar keys alias: $ALIAS"
ok "Network (STELLAR_NETWORK): $NETWORK"
ok "Registry prefix: '${REGISTRY_PREFIX}' (override via REGISTRY_PREFIX env)"
ok "Factory contract: $FACTORY_CONTRACT_ID"

# The upgrade admin for every FRESH contract this script deploys
# (multisig-policy, verifier, factory) — all now carry an admin-gated
# upgrade() (issue #26). Resolved from the deploying alias so each
# __constructor(admin: Address) gets a concrete G-address. Override with
# ADMIN_ADDR to point at a multisig on mainnet (strongly recommended;
# ideally behind an upgrade timelock).
ADMIN_ADDR="${ADMIN_ADDR:-$(stellar keys address "$ALIAS")}"
[ -n "$ADMIN_ADDR" ] || die "could not resolve an admin address (stellar keys address '$ALIAS'; or set ADMIN_ADDR)"
ok "Upgrade admin for fresh deploys: $ADMIN_ADDR"

if [ -z "${SKIP_BUILD:-}" ]; then
    note "Building contracts (set SKIP_BUILD=1 to skip)"
    just build-contracts >/dev/null
    ok "build-contracts complete"
fi

for wasm in "$POLICY_WASM" "$VERIFIER_WASM" "$ACCOUNT_WASM" "$FACTORY_WASM"; do
    [ -f "$wasm" ] || die "expected wasm not found: $wasm (run 'just build-contracts' first)"
done

# --- Task 4: multisig-policy ---------------------------------------------

note "Task 4 · multisig-policy v$POLICY_VERSION"

published_hash="$(fetch_hash "$POLICY_NAME" "$POLICY_VERSION")"
if [ -n "$published_hash" ]; then
    skip "$POLICY_NAME@$POLICY_VERSION already published (hash $published_hash)"
else
    # --wasm-name and --binver override what's read from contract metadata,
    # so we can publish under bare/prefixed names regardless of the
    # crate's Cargo.toml `[package].name` (which is `nido-multisig-policy`).
    stellar registry publish \
        --wasm "$POLICY_WASM" \
        --wasm-name "$POLICY_NAME" \
        --binver "$POLICY_VERSION" \
        --source-account "$ALIAS"
    ok "published $POLICY_NAME@$POLICY_VERSION"
fi

policy_addr="$(fetch_contract_id "$POLICY_NAME")"
if [ -n "$policy_addr" ]; then
    skip "$POLICY_NAME already deployed: $policy_addr"
else
    # multisig-policy now has an admin-gated upgrade() — pass its
    # __constructor(admin) arg via the `--` ctor-arg passthrough.
    stellar registry deploy \
        --contract-name "$POLICY_NAME" \
        --wasm-name "$POLICY_NAME" \
        --version "$POLICY_VERSION" \
        --source-account "$ALIAS" \
        -- --admin "$ADMIN_ADDR"
    policy_addr="$(fetch_contract_id "$POLICY_NAME")"
    ok "deployed $POLICY_NAME: $policy_addr (admin $ADMIN_ADDR)"
fi

# --- Verifier (publish + deploy if missing) -----------------------------

note "verifier · ensure registered by name"

verifier_addr="$(fetch_contract_id "$VERIFIER_NAME")"
if [ -n "$verifier_addr" ]; then
    skip "$VERIFIER_NAME already registered: $verifier_addr"
else
    warn "'$VERIFIER_NAME' is not registered in the registry."
    warn "The factory's pre-upgrade verifier (if any) was lazy-deployed from a"
    warn "hardcoded hash, so it has no registry name. Publishing the current"
    warn "verifier wasm and deploying it under '$VERIFIER_NAME'. The resulting"
    warn "contract address WILL DIFFER from any pre-existing unregistered"
    warn "verifier deployment — accounts created BEFORE this script ran"
    warn "reference the old address; new accounts will use the registered one."

    if [ -z "$(fetch_hash "$VERIFIER_NAME" "$VERIFIER_VERSION")" ]; then
        stellar registry publish \
            --wasm "$VERIFIER_WASM" \
            --wasm-name "$VERIFIER_NAME" \
            --binver "$VERIFIER_VERSION" \
            --source-account "$ALIAS"
        ok "published $VERIFIER_NAME@$VERIFIER_VERSION"
    else
        skip "$VERIFIER_NAME@$VERIFIER_VERSION already published"
    fi

    # The verifier now has an admin-gated upgrade() — pass its
    # __constructor(admin) arg via the `--` ctor-arg passthrough.
    stellar registry deploy \
        --contract-name "$VERIFIER_NAME" \
        --wasm-name "$VERIFIER_NAME" \
        --version "$VERIFIER_VERSION" \
        --source-account "$ALIAS" \
        -- --admin "$ADMIN_ADDR"
    verifier_addr="$(fetch_contract_id "$VERIFIER_NAME")"
    ok "deployed $VERIFIER_NAME: $verifier_addr (admin $ADMIN_ADDR)"
fi

# --- smart-account (publish so the factory's deploy hash is resolvable) ---

note "smart-account · publish v$ACCOUNT_VERSION"

# The factory EMBEDS the smart-account wasm (via include_bytes! in
# contracts/factory/build.rs, which stages the locally-built wasm at
# target/stellar/<network>/smart_account_0_1_0.wasm) and deploys instances by
# sha256 of those embedded bytes. For deploy_v2 to resolve, those EXACT bytes
# must be installed on-chain — that's what this publish/upload step does.
# Publish-only (no deploy): the factory creates account instances at runtime.
# The $ACCOUNT_VERSION here is just the registry label; nothing enforces it
# equals the embedded wasm — the sha256 assertion below does that.
published_account_hash="$(fetch_hash "$ACCOUNT_NAME" "$ACCOUNT_VERSION")"
if [ -n "$published_account_hash" ]; then
    skip "$ACCOUNT_NAME@$ACCOUNT_VERSION already published (hash $published_account_hash)"
else
    stellar registry publish \
        --wasm "$ACCOUNT_WASM" \
        --wasm-name "$ACCOUNT_NAME" \
        --binver "$ACCOUNT_VERSION" \
        --source-account "$ALIAS"
    published_account_hash="$(fetch_hash "$ACCOUNT_NAME" "$ACCOUNT_VERSION")"
    ok "published $ACCOUNT_NAME@$ACCOUNT_VERSION (hash $published_account_hash)"
fi

# Enforce the embed==installed invariant: the factory deploys by
# sha256(embedded wasm), where the embedded wasm IS $ACCOUNT_WASM (factory's
# build.rs embeds exactly this file). If the registry version label points at a
# different hash, upload the embedded bytes directly so deploy_v2 can resolve.
note "smart-account · verify embed==installed hash"

local_account_hash="$(sha256_of "$ACCOUNT_WASM")" \
    || die "could not compute sha256 of $ACCOUNT_WASM (need sha256sum or shasum)"

if [ "$local_account_hash" != "$published_account_hash" ]; then
    warn "$(printf 'smart-account registry hash does not match embedded factory bytes:\n  local  sha256($ACCOUNT_WASM) = %s\n  registry %s@%s        = %s\nUploading embedded wasm directly so factory deploy_v2 can resolve it.' "$local_account_hash" "$ACCOUNT_NAME" "$ACCOUNT_VERSION" "${published_account_hash:-<missing>}")"
    installed_hash="$(stellar contract upload --wasm "$ACCOUNT_WASM" --source-account "$ALIAS" \
        | grep -oE '[0-9a-f]{64}' | tail -1)"
    [ "$installed_hash" = "$local_account_hash" ] \
        || die "uploaded smart-account hash mismatch: expected $local_account_hash, got ${installed_hash:-<empty>}"
    ok "installed embedded smart-account wasm directly: $installed_hash"
else
    ok "embed==installed verified: sha256($ACCOUNT_NAME) = $local_account_hash"
fi

# --- Task 4b: factory fresh-deploy + registry repoint --------------------
#
# The factory's `__constructor(e, admin: Address)` stores the admin that
# alone may call admin()/set_admin()/upgrade(). A constructor only runs at
# DEPLOY time, so an in-place `stellar registry upgrade` of a pre-admin
# factory can NEVER populate the admin slot — admin()/upgrade() would keep
# trapping. Per issue #26's migration plan, the only correct move is to
# deploy a FRESH factory (passing --admin) at a new address and repoint the
# registry `factory` name to it. (The old factory can't self-upgrade.)

note "Task 4b · factory v$FACTORY_VERSION (fresh deploy + repoint)"

published_factory_hash="$(fetch_hash "$FACTORY_NAME" "$FACTORY_VERSION")"
if [ -n "$published_factory_hash" ]; then
    skip "$FACTORY_NAME@$FACTORY_VERSION already published (hash $published_factory_hash)"
else
    stellar registry publish \
        --wasm "$FACTORY_WASM" \
        --wasm-name "$FACTORY_NAME" \
        --binver "$FACTORY_VERSION" \
        --source-account "$ALIAS"
    ok "published $FACTORY_NAME@$FACTORY_VERSION"
fi

# The fresh factory is constructed with the same $ADMIN_ADDR resolved in
# preflight (the deploying alias's key by default, or the ADMIN_ADDR override).
ok "factory admin will be: $ADMIN_ADDR"

# Idempotency guard: if `factory` already resolves to an admin-capable
# contract (admin() returns an address rather than trapping), the fresh
# deploy already happened on a prior run — skip.
registered_factory="$(fetch_contract_id "$FACTORY_NAME")"
existing_admin=""
if [ -n "$registered_factory" ]; then
    existing_admin="$(factory_admin "$registered_factory")"
fi

if [ -n "$existing_admin" ]; then
    skip "$FACTORY_NAME already admin-capable: $registered_factory (admin $existing_admin)"
    new_factory="$registered_factory"
else
    if [ -n "$registered_factory" ]; then
        note "registered $FACTORY_NAME ($registered_factory) predates the admin"
        note "constructor (admin() traps). Deploying a fresh admin-capable factory."
    else
        note "$FACTORY_NAME is not registered yet. Deploying a fresh factory."
    fi

    # Deploy a fresh factory, passing the constructor arg. `stellar contract
    # deploy ... -- --admin <ADDR>` prints the new C-address on stdout.
    new_factory="$(stellar contract deploy \
        --wasm "$FACTORY_WASM" \
        --source-account "$ALIAS" \
        -- --admin "$ADMIN_ADDR" \
        | grep -oE 'C[A-Z0-9]{55}' | head -1)"
    [ -n "$new_factory" ] || die "fresh factory deploy did not return a contract id"
    ok "deployed fresh factory: $new_factory"

    # Repoint (or register) the `factory` registry name to the new address so
    # name-based resolution (SDK/frontend/the factory's own lookups) picks up
    # the admin-capable instance.
    if [ -n "$registered_factory" ]; then
        stellar registry update-contract-address \
            --contract-name "$FACTORY_NAME" \
            --new-address "$new_factory" \
            --source-account "$ALIAS"
        ok "repointed $FACTORY_NAME → $new_factory"
    else
        stellar registry register-contract \
            --contract-name "$FACTORY_NAME" \
            --contract-address "$new_factory" \
            --owner "$ALIAS" \
            --source-account "$ALIAS"
        ok "registered $FACTORY_NAME → $new_factory"
    fi

    warn "The factory address changed to $new_factory."
    warn "Update FACTORY_CONTRACT_ID / the frontend if anything still hardcodes"
    warn "the old address ($FACTORY_CONTRACT_ID). Name-based resolution already"
    warn "tracks the new one via the registry."
fi
registered_factory="$new_factory"

# --- Summary ---------------------------------------------------------

note "Done."
cat <<EOF

Summary:
  $POLICY_NAME@$POLICY_VERSION   $policy_addr
  $VERIFIER_NAME (registered)     $verifier_addr
  $ACCOUNT_NAME@$ACCOUNT_VERSION  $published_account_hash (published)
  $FACTORY_NAME                   $registered_factory (admin-capable, registered by name)

The multisig-policy contract and the WebAuthn verifier are now deployed and
registered. The policy-builder UI on /security can be used against any
existing account to set up recovery rules or delegate session keys —
add_context_rule + the registry resolution happen at the SDK layer, no
factory involvement needed.

Notes:
- The factory now carries an admin (set via __constructor at deploy time),
  so admin()/set_admin()/upgrade() work. A pre-admin factory CANNOT be
  upgraded in place (the constructor only runs on deploy), so this script
  deploys a FRESH factory at a new address and repoints the registry
  '$FACTORY_NAME' name to it. The admin is the deploying alias's public key
  ($ADMIN_ADDR). Newly-created accounts now resolve the verifier by name
  via the registry instead of a hardcoded lazy-deploy hash.
- Both the multisig-policy and the registered verifier are reachable by
  name via 'stellar registry fetch-contract-id <name> --source-account
  <alias>'. The SDK's policyChainFetch.fetchRegistryAddress(name) does the
  same simulate-only lookup at runtime.

Next: the policy-builder UI on /security is operational. Use the inline
forms to set up a recovery rule or delegate a session key on any account.
EOF
