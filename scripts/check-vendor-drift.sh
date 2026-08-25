#!/usr/bin/env bash
# Detect drift in contracts/vendor/ultrahonk-soroban-verifier/src/ -- a
# verbatim copy of an unaudited third-party crate that nothing in this repo
# should ever hand-edit. Computes a deterministic, sorted sha256 manifest of
# that tree and compares it against the committed sibling
# CHECKSUMS.sha256. Any content change, added file, removed file, or rename
# under src/ shows up as a mismatch and fails the check.
#
# Usage: scripts/check-vendor-drift.sh   (safe to run from anywhere -- it
# cd's to the repo root itself, based on this script's own location)
#
# Covers the vendored src/ tree AND the vendor Cargo.toml (so a dependency or
# feature-flag change in the vendored crate can't slip past unnoticed). Also
# asserts the upstream-commit provenance recorded in the vendor Cargo.toml, so a
# bump can't silently drop the record of where the code was vendored from.
#
# NOTE (residual risk): like any checksum guard, the baseline is regenerable, so a
# deliberate hand-edit "passes" once its new hash is committed. Vendor changes must
# stay reviewed, commit-referenced upstream bumps -- this guard is integrity +
# provenance recording, not an authenticity attestation of upstream.
#
# Regenerating the baseline (only when a vendor bump/update is deliberate
# and has been reviewed):
#   { find contracts/vendor/ultrahonk-soroban-verifier/src -type f; \
#     printf '%s\n' contracts/vendor/ultrahonk-soroban-verifier/Cargo.toml; } \
#     | LC_ALL=C sort | xargs sha256sum \
#     > contracts/vendor/ultrahonk-soroban-verifier/CHECKSUMS.sha256
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

VENDOR_DIR="contracts/vendor/ultrahonk-soroban-verifier"
SRC_DIR="${VENDOR_DIR}/src"
VENDOR_MANIFEST="${VENDOR_DIR}/Cargo.toml"
CHECKSUMS_FILE="${VENDOR_DIR}/CHECKSUMS.sha256"

# Provenance of the vendored crate (also recorded in the vendor Cargo.toml + README).
# Integrity (hand-edits) is caught by the checksum manifest below; this asserts the
# separate *provenance* record so a vendor bump can't silently drop where the code
# came from. Update deliberately alongside a reviewed, commit-referenced upstream bump.
UPSTREAM_REPO="https://github.com/yugocabrio/rs-soroban-ultrahonk"
UPSTREAM_REV="3b031847eb043856cc5bcad45bd5a6512370cd16"

# Emits the `find`-plus-Cargo.toml file list the manifest is computed over.
# Single source of truth so the check and the regeneration hint below stay in
# lockstep.
vendor_files() {
  find "${SRC_DIR}" -type f
  printf '%s\n' "${VENDOR_MANIFEST}"
}

if [[ ! -d "${SRC_DIR}" ]]; then
  echo "[!] vendored source dir not found: ${SRC_DIR}" >&2
  exit 1
fi

if [[ ! -f "${CHECKSUMS_FILE}" ]]; then
  echo "[!] checksum baseline not found: ${CHECKSUMS_FILE}" >&2
  exit 1
fi

# Provenance guard: the vendor Cargo.toml must keep recording the upstream commit
# it was retargeted from. (Content integrity of Cargo.toml is also covered by the
# manifest below; this gives a precise, legible failure if the record is dropped.)
if ! grep -qF "${UPSTREAM_REV}" "${VENDOR_MANIFEST}"; then
  echo "[!] vendor provenance missing: ${VENDOR_MANIFEST} no longer records upstream rev ${UPSTREAM_REV}" >&2
  echo "[!] keep the vendored verifier's origin (${UPSTREAM_REPO}) recorded; bump it deliberately + reviewed." >&2
  exit 1
fi

ACTUAL_FILE="$(mktemp)"
trap 'rm -f "${ACTUAL_FILE}"' EXIT

vendor_files | LC_ALL=C sort | xargs sha256sum > "${ACTUAL_FILE}"

if diff -q "${CHECKSUMS_FILE}" "${ACTUAL_FILE}" >/dev/null 2>&1; then
  echo "[ok] vendored verifier tree (${SRC_DIR}) matches ${CHECKSUMS_FILE} -- no drift."
  echo "[ok] provenance: ${UPSTREAM_REPO} @ ${UPSTREAM_REV} (recorded in ${VENDOR_MANIFEST})."
  exit 0
fi

echo "[!] VENDOR DRIFT DETECTED under ${SRC_DIR}" >&2
echo "[!] tree no longer matches ${CHECKSUMS_FILE}. Offending entries:" >&2
diff "${CHECKSUMS_FILE}" "${ACTUAL_FILE}" | grep -E '^[<>]' | while read -r marker _hash path; do
  case "${marker}" in
    "<") echo "    baseline has (missing/changed in tree): ${path}" >&2 ;;
    ">") echo "    tree has (unexpected/changed vs baseline): ${path}" >&2 ;;
  esac
done
echo "[!] If this vendor bump is deliberate and has been reviewed, regenerate the baseline:" >&2
echo "    { find ${SRC_DIR} -type f; printf '%s\\n' ${VENDOR_MANIFEST}; } | LC_ALL=C sort | xargs sha256sum > ${CHECKSUMS_FILE}" >&2
exit 1
