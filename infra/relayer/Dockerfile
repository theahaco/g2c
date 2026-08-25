# Build Caddy WITH the rate-limit plugin (not in the stock apk `caddy`): the
# per-IP token bucket in Caddyfile needs github.com/mholt/caddy-ratelimit
# compiled in. The output is a static Go binary (CGO off), so it runs on the
# Wolfi-glibc relayer base below regardless of the builder's libc.
# Pin both the builder base and the plugin version so this budget-gating proxy is
# reproducible (was `caddy:2-builder` + an unversioned plugin — every rebuild
# re-resolved whatever was latest). caddy-ratelimit is pre-1.0; v0.1.0 is its only
# release, i.e. exactly what the unversioned build already resolved to. The
# `caddy validate` step below fail-closes if a pinned bump ever breaks the config.
FROM docker.io/library/caddy:2.11.4-builder AS caddybuild
RUN xcaddy build --with github.com/mholt/caddy-ratelimit@v0.1.0

FROM docker.io/openzeppelin/openzeppelin-relayer:v1.5.0

USER root
COPY --from=caddybuild /usr/bin/caddy /usr/bin/caddy

COPY plugins/channels /app/plugins/channels
RUN cd /app/plugins/channels && pnpm install --prod --frozen-lockfile \
    && mkdir -p /app/config/keys \
    && chown -R nonroot /app/plugins/channels /app/config

COPY --chown=nonroot config/config.json /app/config/config.json
COPY --chown=nonroot config/networks /app/config/networks
COPY --chown=nonroot Caddyfile /app/Caddyfile
RUN API_KEY=placeholder caddy validate --config /app/Caddyfile --adapter caddyfile
COPY --chown=nonroot entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER nonroot
ENV IN_DOCKER=true
ENTRYPOINT ["/app/entrypoint.sh"]
