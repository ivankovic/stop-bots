# Stop Bots

A TUI that helps you configure your server to stop bad bots and still allow good bots.

# Installation

Use cargo install.

There are no packages currently available.

# Usage

Simply run the binary to launch the TUI.

You can exit the app at any time by hitting 'q'.

You can exit any popup or submenu by hitting the Escape key. Hitting Escape in the main screen will also exit the app.

## Theme

You can switch between the dark and light theme with 'c'. The app will try to auto-detect the theme,
but for some terminal and multiplexer combinations there isn't enough information available to make
the correct choice.

## Main screen

The main screen gives you the overview of the current protections and the most recent overall
metrics. The general design of the UI is this:

--------------------------------------------------------------------------
| System-wide setttings                                                  |
|   - Geo-block [ ALLOWED: CH, DE ]                                      |
|   - Scanners [ BLOCKED ]                                               |
|   - Search Bots [ ALLOWED ]                                            |
|   - AI Bots [ BLOCKED ]                                                |
|                                                                        |
| www.example.org (NGINX: /var/www/html/example.org)                     |
|   - Geo-block [ ALLOWED: CH, DE ]                                      |
|   - Scanners [ BLOCKED ]                                               |
|   - Search Bots [ ALLOWED ]                                            |
|   - AI Bots [ BLOCKED ]                                                |
| ...                                                                    |
--------------------------------------------------------------------------
| Time frame                    Scanners   Search      AI                |
--------------------------------------------------------------------------
| Last 5 minutes                     120       15    2000                |
| Last hour                        12312      123   41231                |
| ...                                                                    |
--------------------------------------------------------------------------

Using the arrow keys (or vim-hjkl navigation) you can select any of the categories. If you
press the Enter of Space key, you can open a configuration popup for that particlar setting, e.g.
the system wide search bot settings.

For example, opening the "Search Bots" setting allows you to togle "ALLOWED" and "BLOCKED" as the
default, and then you can override each particular bot, e.g. "Google Search" can be set to
"BLOCKED", "ALLOWED" or "DEFAULT" individually.

# Contact

You can contact me at [marko@ivankovic.me](marko@ivankovic.me).

# License

Copyright (C) 2026 Marko Ivankovic

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation.

See the [LICENSE](LICENSE) file for the full text of the License.

## Can't use AGPL software?

Alternative licensing is available, for individually negotiated compensation.

[Contact me](mailto:marko@ivankovic.me) for options.

# For Developers, human or otherwise

This part of the README is mostly used to tell the AI how to work in this code. Still, useful for humans too.

## Technology

The project is completely written in Rust.

SQLite is used to store user configuation and other runtime data.

The UI is a Terminal UI written using the excellent Ratatui and Crossterm libraries.

### UI design patterns

The TUI must follow the [Ratatui event driven async template](https://github.com/ratatui/templates/tree/main/event-driven-async).

Each component encapsulates its own state, event handlers, and rendering logic.

## Code quality

Code must always be formatted using the automated standard Rust formatter.

No Rust check errors are allowed. Rust check should be run frequently.

## Testing

Automated tests should be run frequently during coding.

Benchmarks should be used to measure quality. These should be run on demand.

### Automated tests

Each file in src/ should end with the test module for that file, as is typicall in Rust. These tests
should test both happy-path and corner cases.

**Tests in src/ must run in under 1 second**.

Each general user flow should have a test in test/. These should all
be happy-path tests, they should not test errors unless the error is a general user flow.

**Tests in tests/ must run in under 5 seconds.**

### How should tests handle dependencies?

*No mocks*. Mocks prevent testing through the interface and are brittle.

Ideally, the real implementation is used.

When necessary, e.g. for filesystem or database access, fake in-memory implementations should be used.

## Code structure

Rust's project structure must be followed.

Some directories don't exist yet but should be created if the need arises.

<root of the repository>
    |- /src             <- The implementation
        |- main.rs      <- The main entry point, spawns the background threads and the UI
        |- app.rs       <- The app controler, responds to events and controlls the UI
        |- tui/         <- All TUI components go in this directory
            |- SPECS.md <- TUI specs
        |- tui.rs       <- The visual elements of the TUI, the view
        |- db/          <- The db components and specs
            |- SPECS.md <- Database specs
        |- db.rs        <- The SQLite ORM layer, stores the config
        |- nginx.rs     <- Reading and writing NginX config and logs
        |- iptables.rs  <- Integration with iptables
        |- nftables.rs  <- Integration with nftables
    |- /test            <- Integration and end-to-end automated tests
    |- /benches         <- Benchmarks
    |- README.md        <- This file. Only very high level information goes here
    |- AGENTS.md        <- AI-only instructions
    |- SPECS.md         <- Detailed specifications and all decisions that were taken
    |- REVIEW.md        <- Comments about the codebase that need to be improved uppon
    |- TODO.md          <- List of small to  mid size TODO items that need to be fixed in the future

The SPECS.md and README.md files can exist in any subdirectory, and they always serve the same
purpose:

*  README.md - High level summary. Must be readable to humans.
*  SPECS.md - Semi-structured collection of specifications and a decision log of every decision that
   was taken during implementation.

The TODO.md and REVIEW.md files are always only in the root of the repository.
