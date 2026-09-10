# Security Policy

## Supported versions

While the project is `0.0.x` there is exactly one supported version: the latest release.
Fixes go into a new release rather than being backported.

| Version        | Supported |
| -------------- | --------- |
| latest `0.0.x` | yes       |
| anything older | no        |

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/ivankovic/stop-bots/security/advisories/new),
or by email to [marko@ivankovic.me](mailto:marko@ivankovic.me).

Expect an acknowledgement within a week. This is a spare-time project with one
maintainer, so please treat that as the honest figure rather than a service level.

## What counts as a vulnerability here

This tool writes firewall scripts and NGINX configuration on a server it has root-ish
access to, and it runs unattended from cron. The interesting failures are therefore
mostly *integrity* failures, not memory safety:

- **Lockout and denial of service against the operator.** A rule that blocks the
  administrator's own SSH access, or a generated NGINX config that `nginx -t` accepts and
  that then refuses legitimate traffic wholesale. The code has explicit lockout guards; a
  way around one is in scope.
- **Injection into generated config.** A bot name, user agent, hostname or IP address
  from a downloaded list or from a parsed log that escapes quoting and becomes a directive
  in the generated NGINX config or firewall script. Both parsers are fed untrusted input
  by design.
- **Trusting a compromised upstream list.** The bot lists and IP-range feeds are fetched
  over the network from third parties. A response that causes something worse than a bad
  block rule is in scope.
- **Privilege escalation** via the files the tool writes, the database it opens, or the
  subprocesses it spawns (`nginx`, `systemctl`, `nft`, `iptables`).

## What does not

- **Blocking traffic you wanted.** That is the tool working; tune the rules. The README
  is explicit that every detector is off by default for this reason.
- **Requiring root.** Writing firewall rules and NGINX config needs privilege. That is the
  job, not a flaw.
- **The absence of a request-path component.** There is deliberately no runtime component
  in the request path, so anything requiring one (JS challenges, TLS fingerprinting) is a
  missing feature, listed in `TODO.md`, not a vulnerability.
