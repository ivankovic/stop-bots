-- A database as stop-bots 0.0.15 wrote it: `sqlite3 db.sqlite3 .dump` of a file
-- that the 0.0.15 binary, built from its git tag, created and filled through its
-- own CLI (scan-sites over tests/fixtures/nginx, update-bot-lists from
-- tests/fixtures/botlists, add-firewall-rule, block-web-scanners and
-- block-probe-paths over a five-line access log, set-site-rule, exempt-path,
-- set-rate-limit, set-geo-mode, add-country, set-robots-txt, set-probe-paths,
-- set-honeypot-path,
-- set-block-response, set-nginx-commands, trust, set-log-paths and
-- set-auto-apply).
-- The three detect:* settings are what the Dashboard's Automatic blocking
-- panel writes; no CLI verb could, so they were inserted by hand.
--
-- Two edits after the dump: the scanned config paths read /etc/nginx rather
-- than the build machine's checkout, and the two detector blocks expire in
-- 2100 rather than days after the dump, so reading them back does not prune
-- them. user_version is 0, as every 0.0.x left it.
--
-- Committed as SQL rather than as a database file so a diff shows it, and so
-- it never changes: regenerate it only if it turns out not to be what 0.0.15
-- wrote.
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE sources (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                last_fetched_at INTEGER,
                bot_count INTEGER NOT NULL DEFAULT 0
            );
INSERT INTO sources VALUES('well-known-bots','ArcJet Well-Known Bots','https://raw.githubusercontent.com/arcjet/well-known-bots/main/well-known-bots.json',1790588764,4);
INSERT INTO sources VALUES('ai-robots-txt','ai.robots.txt','https://raw.githubusercontent.com/ai-robots-txt/ai.robots.txt/main/robots.json',1790588764,2);
CREATE TABLE bots (
                id INTEGER PRIMARY KEY,
                slug TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                is_ai INTEGER NOT NULL DEFAULT 0,
                is_search_engine INTEGER NOT NULL DEFAULT 0,
                is_scanner INTEGER NOT NULL DEFAULT 0,
                user_agent_pattern TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'default',
                source_id TEXT NOT NULL REFERENCES sources(id),
                updated_at INTEGER NOT NULL
            );
INSERT INTO bots VALUES(1,'ai-search-bot','Ai Search Bot',1,0,0,'AISearchBot','default','well-known-bots',1790588764);
INSERT INTO bots VALUES(2,'google-crawler','Google Crawler',0,1,0,'Googlebot\/','default','well-known-bots',1790588764);
INSERT INTO bots VALUES(3,'jyxo-crawler','Jyxo Crawler',0,0,0,'jyxobot','default','well-known-bots',1790588764);
INSERT INTO bots VALUES(4,'mixed-pattern-bot','Mixed Pattern Bot',1,0,0,'GoodBot','default','well-known-bots',1790588764);
INSERT INTO bots VALUES(5,'chatgpt-agent','ChatGPT Agent',1,0,0,'ChatGPT Agent','default','ai-robots-txt',1790588764);
INSERT INTO bots VALUES(6,'gptbot','GPTBot',1,0,0,'GPTBot','default','ai-robots-txt',1790588764);
CREATE TABLE bot_source_entries (
                slug TEXT NOT NULL,
                source_id TEXT NOT NULL REFERENCES sources(id),
                name TEXT NOT NULL,
                is_ai INTEGER NOT NULL DEFAULT 0,
                is_search_engine INTEGER NOT NULL DEFAULT 0,
                is_scanner INTEGER NOT NULL DEFAULT 0,
                user_agent_pattern TEXT NOT NULL,
                PRIMARY KEY (slug, source_id)
            );
INSERT INTO bot_source_entries VALUES('ai-search-bot','well-known-bots','Ai Search Bot',1,0,0,'AISearchBot');
INSERT INTO bot_source_entries VALUES('google-crawler','well-known-bots','Google Crawler',0,1,0,'Googlebot\/');
INSERT INTO bot_source_entries VALUES('jyxo-crawler','well-known-bots','Jyxo Crawler',0,0,0,'jyxobot');
INSERT INTO bot_source_entries VALUES('mixed-pattern-bot','well-known-bots','Mixed Pattern Bot',1,0,0,'GoodBot');
INSERT INTO bot_source_entries VALUES('chatgpt-agent','ai-robots-txt','ChatGPT Agent',1,0,0,'ChatGPT Agent');
INSERT INTO bot_source_entries VALUES('gptbot','ai-robots-txt','GPTBot',1,0,0,'GPTBot');
CREATE TABLE sites (
                id INTEGER PRIMARY KEY,
                server_name TEXT NOT NULL,
                config_path TEXT NOT NULL,
                discovered_at INTEGER NOT NULL,
                UNIQUE(server_name, config_path)
            );
INSERT INTO sites VALUES(1,'example.com','/etc/nginx/sites-enabled/example.com',1790588764);
INSERT INTO sites VALUES(2,'localhost','/etc/nginx/conf.d/server.conf',1790588764);
CREATE TABLE settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
INSERT INTO settings VALUES('default_status_scanner','blocked');
INSERT INTO settings VALUES('default_status_search','allowed');
INSERT INTO settings VALUES('default_status_ai','blocked');
INSERT INTO settings VALUES('geo_mode','allowlist');
INSERT INTO settings VALUES('rate_limit_rps','7');
INSERT INTO settings VALUES('rate_limit_burst','11');
INSERT INTO settings VALUES('rate_limit_enabled','true');
INSERT INTO settings VALUES('serve_robots_txt','true');
INSERT INTO settings VALUES('detect_probe_paths_extra','/secret-admin/');
INSERT INTO settings VALUES('detect_honeypot_path','/my-trap/');
INSERT INTO settings VALUES('block_response','410');
INSERT INTO settings VALUES('nginx:test_command','/bin/true');
INSERT INTO settings VALUES('nginx:reload_command','/bin/true');
INSERT INTO settings VALUES('logs:access_path','/srv/log/access.log');
INSERT INTO settings VALUES('auto_apply','true');
INSERT INTO settings VALUES('detect:block_web_scanners:enabled','false');
INSERT INTO settings VALUES('detect:block_asset_ratio:enabled','true');
INSERT INTO settings VALUES('detect:block_probe_paths:ttl_days','9');
CREATE TABLE firewall_rules (
                id INTEGER PRIMARY KEY,
                address TEXT NOT NULL,
                port INTEGER,
                action TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                expires_at INTEGER
            );
INSERT INTO firewall_rules VALUES(1,'203.0.113.7',NULL,'block',1,1790588764,NULL);
INSERT INTO firewall_rules VALUES(2,'198.51.100.0/24',22,'block',1,1790588764,NULL);
INSERT INTO firewall_rules VALUES(3,'192.0.2.1',NULL,'allow',1,1790588764,NULL);
INSERT INTO firewall_rules VALUES(4,'198.51.100.23',NULL,'block',1,1790588764,4102444800);
INSERT INTO firewall_rules VALUES(5,'203.0.113.99',NULL,'block',1,1790588764,4102444800);
CREATE TABLE site_category_overrides (
                site_id INTEGER NOT NULL REFERENCES sites(id),
                category TEXT NOT NULL,
                policy TEXT NOT NULL,
                PRIMARY KEY (site_id, category)
            );
CREATE TABLE site_bot_overrides (
                site_id INTEGER NOT NULL REFERENCES sites(id),
                bot_id INTEGER NOT NULL REFERENCES bots(id),
                policy TEXT NOT NULL,
                PRIMARY KEY (site_id, bot_id)
            );
CREATE TABLE site_path_exemptions (
                site_id INTEGER NOT NULL REFERENCES sites(id),
                path TEXT NOT NULL,
                PRIMARY KEY (site_id, path)
            );
INSERT INTO site_path_exemptions VALUES(1,'/blog/');
CREATE TABLE site_agent_exemptions (
                site_id INTEGER NOT NULL REFERENCES sites(id),
                path TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                PRIMARY KEY (site_id, path, user_agent)
            );
CREATE TABLE site_request_rules (
                site_id INTEGER NOT NULL REFERENCES sites(id),
                rule TEXT NOT NULL,
                PRIMARY KEY (site_id, rule)
            );
INSERT INTO site_request_rules VALUES(1,'http_1x');
CREATE TABLE ip_range_sources (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                category TEXT NOT NULL,
                last_fetched_at INTEGER,
                range_count INTEGER NOT NULL DEFAULT 0
            );
CREATE TABLE ip_ranges (
                source_id TEXT NOT NULL REFERENCES ip_range_sources(id),
                cidr TEXT NOT NULL,
                PRIMARY KEY (source_id, cidr)
            );
CREATE TABLE country_ip_ranges (
                country_code TEXT NOT NULL,
                cidr TEXT NOT NULL,
                fetched_at INTEGER NOT NULL,
                PRIMARY KEY (country_code, cidr)
            );
CREATE TABLE selected_countries (
                country_code TEXT PRIMARY KEY,
                added_at INTEGER NOT NULL
            );
INSERT INTO selected_countries VALUES('hr',1790588765);
CREATE TABLE user_agent_stats (
                user_agent TEXT PRIMARY KEY,
                hit_count INTEGER NOT NULL DEFAULT 0,
                last_seen_at INTEGER NOT NULL
            );
CREATE TABLE reputation_sources (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                last_fetched_at INTEGER,
                range_count INTEGER NOT NULL DEFAULT 0
            );
CREATE TABLE reputation_ranges (
                source_id TEXT NOT NULL REFERENCES reputation_sources(id),
                cidr TEXT NOT NULL,
                PRIMARY KEY (source_id, cidr)
            );
CREATE TABLE blocked_user_agents (
                user_agent TEXT PRIMARY KEY,
                blocked_at INTEGER NOT NULL
            );
CREATE TABLE ssh_login_ips (
                address TEXT PRIMARY KEY,
                seen_at INTEGER NOT NULL
            );
CREATE TABLE trusted_addresses (
                address TEXT PRIMARY KEY,
                trusted_at INTEGER NOT NULL
            );
INSERT INTO trusted_addresses VALUES('192.0.2.77',1790588765);
CREATE TABLE trusted_user_agents (
                user_agent TEXT PRIMARY KEY,
                trusted_at INTEGER NOT NULL
            );
INSERT INTO trusted_user_agents VALUES('MyUptimeChecker',1790588765);
COMMIT;
