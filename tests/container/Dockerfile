# A real server, for tests that need one.
#
# Base pinned to ubuntu:24.04 to match the development host's glibc
# (2.39): the stop-bots binary is built on the host and copied in rather
# than compiled here, which keeps a container run to seconds instead of a
# full rebuild. If the host's glibc ever moves ahead of this base, the
# binary won't start and the harness will say so loudly rather than
# silently skipping.
FROM ubuntu:24.04

RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        nginx nftables curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# NGINX in the foreground, logging where the tool expects to find it.
RUN mkdir -p /var/log/nginx /etc/stop-bots /run/nginx

# There is no init system in a container, so `systemctl reload nginx` --
# which `batch --apply` and the TUI both shell out to -- has nothing to
# talk to. This shim stands in for it, the same substitution the harness
# already makes when it calls `nginx -s reload` by hand. It exists so that
# `--apply` can be tested as the single command an admin actually runs,
# rather than as its two halves separately.
RUN printf '%s\n' \
        '#!/bin/sh' \
        '[ "$1" = reload ] && exec nginx -s reload' \
        'exit 0' \
        > /usr/local/bin/systemctl && chmod +x /usr/local/bin/systemctl

COPY stop-bots /usr/local/bin/stop-bots
COPY site.conf /etc/nginx/sites-enabled/test-site.conf
RUN rm -f /etc/nginx/sites-enabled/default

CMD ["sleep", "infinity"]
