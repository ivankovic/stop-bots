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

    let ctx = Ctx::for_request(&auth.csrf, &state).await;
    render(Tab::Help, &ctx, flash.into_flash(), body(&view))
}

fn body(view: &View) -> Markup {
    html! {
        .cols {

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
            "Reaching this console from outside",
            Some("What the Dashboard\u{2019}s Web Access panel \u{2014} and the TUI\u{2019}s w key \u{2014} writes"),
            html! {
                table { tbody {
                    (row(
                        "Path on an existing site",
                        html! {
                            "The default, and the safer one: it adds a "
                            code { "location" }
                            " block to a site you pick, so this console inherits that site\u{2019}s "
                            "certificate. It goes in the site\u{2019}s TLS "
                            code { "server" }
                            " block, not its port-80 redirect \u{2014} a login form does not belong on "
                            "the cleartext half of a site that has a certificate."
                        },
                    ))
                    (row(
                        "Its own subdomain",
                        html! {
                            "Writes a new "
                            code { "server" }
                            " block on port 80. Until you run "
                            code { "certbot --nginx -d <host>" }
                            " this console\u{2019}s password form and session cookie cross the network "
                            "in the clear; the generated file says so too. Set "
                            code { "web:secure_cookie" }
                            " once the certificate is in place."
                        },
                    ))
                    (row(
                        "Three things, not one",
                        html! {
                            "The panel also records the path prefix and adds the host name to the "
                            "allowlist above, because this server matches the full path "
                            strong { "including" }
                            " the prefix and refuses a request carrying a host it was not told "
                            "about. Miss either and you get a 404 or a 403 that looks like a broken "
                            "console rather than a missing setting. A changed prefix needs a "
                            "restart to take effect."
                        },
                    ))
                    (row(
                        "If the config does not parse",
                        html! {
                            "It is validated with "
                            code { "nginx -t" }
                            " before it can take effect, and rolled back if that fails \u{2014} a new "
                            code { "server" }
                            " block that does not parse would otherwise leave the whole config "
                            "unloadable while the running NGINX carried on serving from memory, so "
                            "the breakage would surface at somebody else\u{2019}s reload."
                        },
                    ))
                } }
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
            "The two buttons that change the host",
            Some("In the header, on every screen \u{2014} what they touch, and what stops them going wrong"),
            html! {
                .panel-body {
                    p .hint {
                        "\u{201c}Update everything\u{201d} downloads every bot list, every "
                        "enabled reputation feed, the crawler IP ranges, and the ranges for "
                        "every country you selected \u{2014} one source failing does not stop "
                        "the rest. \u{201c}Apply everything\u{201d} then writes and reloads "
                        "the NGINX config and writes and runs the firewall script, the same "
                        "two halves, and in the same order, as "
                        code { "stop-bots batch --apply" }
                        "."
                    }
                }
                table { tbody {
                    (row(
                        "Apply everything",
                        html! {
                            "Writes and reloads the NGINX config, then writes and "
                            strong { "runs" }
                            " the firewall script. The two are independent: whichever fails, the "
                            "other still gets its turn, because a half-applied host beats one where "
                            "an NGINX syntax error also left the firewall stale. Applying the "
                            "firewall used to be deliberately absent from this console; it is here "
                            "now, behind the guards below."
                        },
                    ))
                    (row(
                        "Update everything",
                        html! {
                            "Downloads every bot list, every crawler IP range, every "
                            strong { "enabled" }
                            " reputation feed and every "
                            strong { "selected" }
                            " country — the same set "
                            code { "stop-bots batch" }
                            " fetches, from the same plan. Nothing is enforced until something "
                            "applies it."
                        },
                    ))
                    (row(
                        "Before the firewall script runs",
                        html! {
                            "The rules are checked against the clients currently logged in over "
                            "SSH, in the order the script itself will evaluate them. A rule that "
                            "would block one of them is a "
                            strong { "refusal" }
                            " — nothing is written and nothing runs. That is the same guard "
                            code { "stop-bots batch --apply" }
                            " uses, and it is what makes a one-click apply defensible."
                        },
                    ))
                    (row(
                        "The same two in the TUI",
                        html! {
                            "The terminal UI has both on its Dashboard as single keys \u{2014} "
                            code { "u" }
                            " updates everything and "
                            code { "a" }
                            " applies everything \u{2014} driving the same code this page "
                            "describes, not a second implementation. "
                            code { "w" }
                            " opens the same Web Access form."
                        },
                    ))
                    (row(
                        "Turning it back off",
                        html! {
                            "Start the console with "
                            code { "stop-bots web --no-apply" }
                            " and it writes both the config and the script but runs neither, which "
                            "is how it behaved before. The row above says which mode this console "
                            "is in."
                        },
                    ))
                } }
            },
        ))

        (layout::panel(
            "What this screen cannot do",
            Some("Deliberate omissions, each with the reason"),
            html! {
                table { tbody {
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
                            "Bot settings instead, or "
                            strong { "Trust" }
                            " it: trust outranks every list, and no refresh undoes it."
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
                        "The NGINX screen owns everything that ends up in "
                        strong { "NGINX config" }
                        ": what a blocked request gets back, the generated robots.txt, rate limiting, "
                        "and each site's own overrides."
                    }
                    p .hint {
                        "That is the same split the TUI makes."
                    }
                }
            },
        ))

        }
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
            "Change the password from the browser",
            "Block the address you are connected from",
            "Unblock something a list blocked",
        ] {
            assert!(rendered.contains(expected), "{expected} missing");
        }
    }

    /// The console applies the firewall script now. This page used to list
    /// that as something it deliberately would not do, which is a promise
    /// the code no longer keeps — and a help screen that is confidently
    /// wrong is worse than one that is silent.
    #[test]
    fn the_help_does_not_still_promise_that_the_firewall_is_never_applied() {
        let rendered = body(&view(true)).into_string();

        assert!(
            !rendered.contains("running it is not"),
            "the retired omission is still on the page:\n{rendered}"
        );
        assert!(
            rendered.contains("Apply everything"),
            "the button that does it is not explained"
        );
        assert!(
            rendered.contains("refusal"),
            "the anti-lockout guard is what makes it defensible, so it has to be stated"
        );
    }

    /// These three used to be console-only, and this page said so by
    /// omission. The TUI has all three now, and a help screen that still
    /// implies otherwise sends someone to a browser they did not need —
    /// the same failure mode as the retired firewall omission above.
    #[test]
    fn the_help_says_the_tui_has_the_same_three_actions() {
        let rendered = body(&view(true)).into_string();

        assert!(
            rendered.contains("The same two in the TUI"),
            "the TUI equivalents are not mentioned:\n{rendered}"
        );
        for key in ["<code>u</code>", "<code>a</code>", "<code>w</code>"] {
            assert!(rendered.contains(key), "{key} is not named:\n{rendered}");
        }
    }

    /// The buttons live in the header, which is where someone reading
    /// this has to go to find them.
    #[test]
    fn the_help_names_the_panel_the_buttons_live_in() {
        let rendered = body(&view(true)).into_string();
        assert!(
            rendered.contains("In the header, on every screen"),
            "the page never says where the buttons are:\n{rendered}"
        );
    }

    /// Both halves of the Web Access panel, including the one that is a
    /// real downgrade if nobody mentions it.
    #[test]
    fn the_help_explains_both_web_access_modes_and_the_cleartext_caveat() {
        let rendered = body(&view(true)).into_string();

        assert!(
            rendered.contains("Path on an existing site"),
            "path mode missing"
        );
        assert!(
            rendered.contains("Its own subdomain"),
            "subdomain mode missing"
        );
        assert!(
            rendered.contains("in the clear"),
            "the cleartext caveat must be on the page"
        );
        assert!(
            rendered.contains("certbot --nginx -d &lt;host&gt;"),
            "the fix for it has to be there too"
        );
    }

    #[test]
    fn a_configured_host_name_is_escaped() {
        let mut v = view(false);
        v.allowed_hosts = vec!["<script>alert(1)</script>".into()];
        let rendered = body(&v).into_string();
        assert!(!rendered.contains("<script>alert(1)"), "was: {rendered}");
    }
}
