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

COPY stop-bots /usr/local/bin/stop-bots
COPY site.conf /etc/nginx/sites-enabled/test-site.conf
RUN rm -f /etc/nginx/sites-enabled/default

CMD ["sleep", "infinity"]
