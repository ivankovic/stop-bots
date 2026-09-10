/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! Help.
//!
//! The TUI's Help screen is a key-binding reference, which a browser does
//! not need. What the web UI's reader needs instead is the two things the
//! console cannot tell them by rendering a table: what is *not* here, and
//! how this thing is exposed.

use axum::extract::{Query, State};
use axum::response::Response;
use maud::{html, Markup};

use crate::web::layout::{self, Ctx, PillKind, Tab};
use crate::web::server::{internal_error, render, Auth, FlashQuery};
use crate::web::state::AppState;

struct View {
    bind: String,
    loopback: bool,
    allowed_hosts: Vec<String>,
    trusts_forwarded: bool,
    secure_cookie: bool,
    nginx_test: String,
    nginx_reload: String,
    apply_for_real: bool,
    nginx_root: String,
}

pub async fn page(
    State(state): State<AppState>,
    auth: Auth,
    Query(flash): Query<FlashQuery>,
) -> Response {
    let apply_for_real = state.apply_for_real;
    let nginx_root = state.nginx_root.display().to_string();

    let view = state
        .with_db(move |db| {
            let bind = crate::web::resolve_bind(db, None)?;
            let commands = crate::nginx::NginxCommands::from_db(db)?;
            Ok(View {
                loopback: crate::web::is_loopback(&bind),
                bind: bind.to_string(),
                allowed_hosts: crate::web::configured_hosts(db)?,
                trusts_forwarded: db.get_bool_setting(crate::web::TRUST_FORWARDED_KEY, false)?,
                secure_cookie: db.get_bool_setting(crate::web::SECURE_COOKIE_KEY, false)?,
                nginx_test: commands.test.join(" "),
                nginx_reload: commands.reload.join(" "),
                apply_for_real,
                nginx_root,
            })
        })
        .await;

    let view = match view {
        Ok(view) => view,
        Err(err) => return internal_error(&err.to_string()),
    };

    let ctx = Ctx::new(auth.csrf.clone(), state.base.clone());
    render(Tab::Help, &ctx, flash.into_flash(), body(&view))
}

fn body(view: &View) -> Markup {
    html! {
        (layout::panel(
            "How this console is exposed",
            None,
            html! {
                table { tbody {
                    tr {
                        td { "Bound to" }
                        td .mono { (view.bind) }
                        td {
                            @if view.loopback {
                                (layout::pill("LOOPBACK ONLY", PillKind::Allowed))
                            } @else {
                                (layout::pill("REACHABLE FROM THE NETWORK", PillKind::Warn))
                            }
                        }
                    }
                    tr {
                        td { "Answers to host names" }
                        td colspan="2" {
                            "localhost, 127.0.0.1, ::1"
                            @for host in &view.allowed_hosts {
                                ", " span .mono { (host) }
                            }
                        }
                    }
                    tr {
                        td { "Session cookie is Secure" }
                        td colspan="2" {
                            @if view.secure_cookie {
                                (layout::pill("YES", PillKind::Allowed))
                            } @else {
                                (layout::pill("NO", PillKind::Neutral))
                                span .hint { " Behind TLS this should be on, or a browser will send the session to an http:// URL too." }
                            }
                        }
                    }
                    tr {
                        td { "Believes X-Forwarded-For" }
                        td colspan="2" {
                            @if view.trusts_forwarded {
                                (layout::pill("YES", PillKind::Warn))
                                span .hint { " Only safe if a proxy really does overwrite it." }
                            } @else {
                                (layout::pill("NO", PillKind::Neutral))
                            }
                        }
                    }
                } }
                .panel-body {
                    @if view.loopback {
                        p .hint {
                            "Reach it from your machine with an SSH tunnel: "
                            code { "ssh -L 8787:127.0.0.1:8787 <this-host>" }
                            ", then open " code { "http://127.0.0.1:8787/" } "."
                        }
                    } @else {
                        p .hint {
                            "This console can rewrite the firewall and the NGINX config of the host "
                            "it runs on. Exposed, it should sit behind TLS and behind this tool's own "
                            "protection — and the host allowlist above should name exactly the name "
                            "you use, because that is what makes DNS rebinding fail."
                        }
                    }
                }
            },
        ))

        (layout::panel(
            "What this host is configured to run",
            None,
            html! {
                table { tbody {
                    tr { td { "NGINX config root" } td .mono { (view.nginx_root) } }
                    tr { td { "Config test" } td .mono { (view.nginx_test) } }
                    tr { td { "Reload" } td .mono { (view.nginx_reload) } }
                    tr {
                        td { "Applying reloads NGINX" }
                        td {
                            @if view.apply_for_real {
                                "yes"
                            } @else {
                                "no — started with --no-apply"
                            }
                        }
                    }
                } }
                .panel-body {
                    p .hint {
                        "Running NGINX in a container? Point both commands at it with "
                        code { "stop-bots set-nginx-commands --test \"docker exec web nginx -t\" --reload \"docker exec web nginx -s reload\"" }
                        "."
                    }
                }
            },
        ))

        (layout::panel(
            "What this screen cannot do",
            Some("Deliberate omissions, each with the reason"),
            html! {
                table { tbody {
                    (row(
                        "Apply the firewall script",
                        html! {
                            "Writing it is here; running it is not. A written script is inert, and "
                            "putting the one operation that can take the host off the network a "
                            "single click away in a browser is not a trade this UI makes. Run it "
                            "yourself, or from cron with "
                            code { "stop-bots batch --apply" }
                            "."
                        },
                    ))
                    (row(
                        "Download country or crawler IP ranges",
                        html! {
                            "Bot lists update from here because they are small and quick. The range "
                            "feeds are neither. Use "
                            code { "stop-bots update-country-ranges" }
                            " and "
                            code { "stop-bots update-ip-ranges" }
                            ", or let the scheduled tasks do it."
                        },
                    ))
                    (row(
                        "Change the password from the browser",
                        html! {
                            "A console whose password can be changed by whoever is already looking "
                            "at it gains nothing from the change. "
                            code { "stop-bots web --set-password" }
                            " on the host, where being able to run it already means having the box."
                        },
                    ))
                    (row(
                        "Block the address you are connected from",
                        html! {
                            "Refused, because it would take away the console you would use to undo "
                            "it. The equivalent guard for SSH is what stops the firewall script "
                            "locking you out."
                        },
                    ))
                    (row(
                        "Unblock something a list blocked",
                        html! {
                            "Rows tagged " (layout::pill("BLOCKLIST", PillKind::Warn)) " come from a "
                            "downloaded list. An unblock here would be undone by the next refresh of "
                            "that list, so the button is not offered — change the bot's setting on "
                            "Bot settings instead."
                        },
                    ))
                } }
            },
        ))

        (layout::panel(
            "The split between the two settings screens",
            None,
            html! {
                .panel-body {
                    p {
                        "The Dashboard owns everything that ends up in the "
                        strong { "firewall script" }
                        ": categories of known bot, geo-blocking, the detectors that read your logs, "
                        "and the third-party IP feeds."
                    }
                    p {
                        "Site settings owns everything that ends up in "
                        strong { "NGINX config" }
                        ": what a blocked request gets back, the generated robots.txt, rate limiting, "
                        "and each site's own overrides."
                    }
                    p .hint {
                        "That is the same split the TUI makes, and it is what decides where any given "
                        "setting lives."
                    }
                }
            },
        ))
    }
}

fn row(title: &str, detail: Markup) -> Markup {
    html! {
        tr {
            td style="width:16em;vertical-align:top" { strong { (title) } }
            td { (detail) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(loopback: bool) -> View {
        View {
            bind: if loopback {
                "127.0.0.1:8787"
            } else {
                "0.0.0.0:8787"
            }
            .into(),
            loopback,
            allowed_hosts: vec![],
            trusts_forwarded: false,
            secure_cookie: false,
            nginx_test: "nginx -t".into(),
            nginx_reload: "systemctl reload nginx".into(),
            apply_for_real: true,
            nginx_root: "/etc/nginx".into(),
        }
    }

    #[test]
    fn a_loopback_bind_is_told_apart_from_an_exposed_one() {
        let local = body(&view(true)).into_string();
        assert!(local.contains("LOOPBACK ONLY"), "was: {local}");
        assert!(local.contains("ssh -L"), "the tunnel is the recommendation");

        let exposed = body(&view(false)).into_string();
        assert!(exposed.contains("REACHABLE FROM THE NETWORK"));
        assert!(
            exposed.contains("DNS rebinding"),
            "an exposed console should say what the host allowlist is for"
        );
    }

    #[test]
    fn the_page_names_the_configured_nginx_commands() {
        let mut v = view(true);
        v.nginx_reload = "docker exec web nginx -s reload".into();
        let rendered = body(&v).into_string();
        assert!(rendered.contains("docker exec web nginx -s reload"));
    }

    #[test]
    fn the_omissions_are_listed_with_their_reasons() {
        let rendered = body(&view(true)).into_string();
        for expected in [
            "Apply the firewall script",
            "Change the password from the browser",
            "Block the address you are connected from",
        ] {
            assert!(rendered.contains(expected), "{expected} missing");
        }
    }

    #[test]
    fn a_configured_host_name_is_escaped() {
        let mut v = view(false);
        v.allowed_hosts = vec!["<script>alert(1)</script>".into()];
        let rendered = body(&v).into_string();
        assert!(!rendered.contains("<script>alert(1)"), "was: {rendered}");
    }
}
