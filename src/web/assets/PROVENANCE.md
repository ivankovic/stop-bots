# Vendored assets

Checked in rather than fetched at build time, so that building this project
needs no network and the bytes that ship are the bytes that were reviewed.

| File          | Version | Source                                                            | SHA-256                                                            |
| ------------- | ------- | ----------------------------------------------------------------- | ------------------------------------------------------------------ |
| `htmx.min.js` | 2.0.4   | https://cdnjs.cloudflare.com/ajax/libs/htmx/2.0.4/htmx.min.js      | `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447` |

Verify with:

```
sha256sum src/web/assets/htmx.min.js
```

## Why vendored and not a CDN link

The web UI is an administration console for a server that is, by
assumption, under attack. Loading a script from a third-party origin would
mean that origin can execute arbitrary code in the page that rewrites the
firewall — and it would also mean the console stops working on a host with
no outbound access, which is a deployment this project explicitly supports
everywhere else (`--source` on every downloader).

The Content-Security-Policy this server sends has no `script-src` for any
external origin, so a CDN link would be blocked even if one were added by
accident.

## Upgrading

Download the new version, update the row above with its digest, and read
the changelog. htmx is a single file with no build step, which is most of
why it was chosen.
