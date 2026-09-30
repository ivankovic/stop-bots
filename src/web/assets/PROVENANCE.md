# Vendored assets

Checked in rather than fetched at build time, so that building this project
needs no network and the bytes that ship are the bytes that were reviewed.

There are none at present. htmx 2.0.4 was vendored here until 0.1.0; it was
loaded on every page and used by none, and it was removed rather than kept
as a way for an HTML-injection bug to make authorised requests. If a
third-party file is ever added, list it here with its version, source URL
and SHA-256, so it can be checked with `sha256sum`.

## Why vendored and not a CDN link

The web UI is an administration console for a server that is, by
assumption, under attack. Loading a script from a third-party origin would
mean that origin can execute arbitrary code in the page that rewrites the
firewall — and it would also mean the console stops working on a host with
no outbound access, which is a deployment this project explicitly supports
everywhere else (`--source` on every downloader).

The Content-Security-Policy this server sends allows no script file at all,
only the one inline script by its hash, so a CDN link would be blocked even
if one were added by accident.
