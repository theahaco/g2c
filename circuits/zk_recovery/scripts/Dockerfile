# bb 3.x requires glibc >= 2.38. On hosts that ship an older glibc (e.g.
# Ubuntu/Pop!_OS 22.04, glibc 2.35), `bb` can't run natively. This image
# gives gen_artifacts.sh a throwaway Ubuntu 24.04 container with the same
# nargo/bb versions installed as the local toolchain, so `just
# build-circuits` still works. Mirrors
# ../../../../zk/rs-soroban-ultrahonk/scripts/circuits.Dockerfile (a sibling
# repo's identical fix for the same problem), trimmed to what this circuit
# needs (no Rust toolchain -- we don't build any Rust example here).
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV NOIR_VERSION=1.0.0-beta.18
# Keep in lockstep with REQUIRED_BB_VERSION in gen_artifacts.sh. bbup resolves bb
# from the noir version via a mapping that lives in the (unpinned) upstream bbup
# script, so the resolved bb is asserted below -- a mapping/installer drift fails
# the image build here instead of silently changing the VK/proof.
ENV BB_VERSION=3.0.0-nightly.20260102

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        curl ca-certificates git xxd python3 && \
    rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.nargo/bin:/root/.bb:${PATH}"

RUN curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash && \
    /root/.nargo/bin/noirup -v ${NOIR_VERSION}

RUN curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash && \
    /root/.bb/bbup -nv ${NOIR_VERSION}

# Fail the build (do NOT swallow with `|| true`) if the resolved toolchain drifts
# from the pins: a silent bb/nargo change would produce a different VK/proof for
# byte-identical ACIR. Mirrors gen_artifacts.sh's REQUIRED_BB_VERSION guard.
RUN set -eu; \
    nargo --version | grep -qF "${NOIR_VERSION}" \
      || { echo "[!] nargo mismatch: want ${NOIR_VERSION}, got $(nargo --version 2>&1)" >&2; exit 1; }; \
    bb --version | grep -qF "${BB_VERSION}" \
      || { echo "[!] bb mismatch: want ${BB_VERSION}, got $(bb --version 2>&1)" >&2; exit 1; }

WORKDIR /work
