-- A database as stop-bots 0.11.0 wrote it: `sqlite3 db.sqlite3 .dump` of a
-- file the released 0.11.0 binary created and filled through its own CLI.
-- Made by scripts/upgrade-fixture.sh, which lists every command; regenerate
-- it only if it turns out not to be what 0.11.0 wrote.
--
-- `.dump` leaves out the schema version, so it is added as the last line.
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE sources (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                last_fetched_at INTEGER,
                bot_count INTEGER NOT NULL DEFAULT 0
            );
INSERT INTO sources VALUES('well-known-bots','ArcJet Well-Known Bots','https://raw.githubusercontent.com/arcjet/well-known-bots/main/well-known-bots.json',1794330854,5);
INSERT INTO sources VALUES('ai-robots-txt','ai.robots.txt','https://raw.githubusercontent.com/ai-robots-txt/ai.robots.txt/main/robots.json',NULL,0);
INSERT INTO sources VALUES('nginx-bad-bots','Nginx Ultimate Bad Bot Blocker','https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list',NULL,0);
INSERT INTO sources VALUES('stop-bots-extras','stop-bots enhanced list','https://github.com/ivankovic/stop-bots/blob/main/src/botlist/stop_bots_extras.rs',1794330854,204);
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
INSERT INTO bots VALUES(1,'ai-search-bot','Ai Search Bot',1,0,0,'AISearchBot','default','well-known-bots',1794330854);
INSERT INTO bots VALUES(2,'google-crawler','Google Crawler',0,1,0,'Googlebot\/','default','well-known-bots',1794330854);
INSERT INTO bots VALUES(3,'jyxo-crawler','Jyxo Crawler',0,0,0,'jyxobot','default','well-known-bots',1794330854);
INSERT INTO bots VALUES(4,'mixed-pattern-bot','Mixed Pattern Bot',1,0,0,'GoodBot','default','well-known-bots',1794330854);
INSERT INTO bots VALUES(5,'trailing-backslash-bot','Trailing Backslash Bot',1,0,0,'Trailing\\','default','well-known-bots',1794330854);
INSERT INTO bots VALUES(6,'let-s-encrypt-validation','Let''s Encrypt validation',0,0,0,'Let''s Encrypt','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(7,'qwantbot','Qwantbot',0,1,0,'Qwantbot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(8,'googlebot-unversioned','Googlebot (unversioned)',0,1,0,'Googlebot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(9,'xai-searchbot','xAI-SearchBot',1,0,0,'xAI-SearchBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(10,'xai-grok','xAI-Grok',1,0,0,'xAI-Grok','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(11,'grokbot','GrokBot',1,0,0,'GrokBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(12,'moonshotbot-kimi','MoonshotBot (Kimi)',1,0,0,'MoonshotBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(13,'hunyuan-tencent','Hunyuan (Tencent)',1,0,0,'Hunyuan','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(14,'yibot-01-ai','YiBot (01.AI)',1,0,0,'YiBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(15,'silovik','Silovik',0,0,1,'Silovik','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(16,'pathscan','pathscan',0,0,1,'pathscan','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(17,'cyberconvoyscout','CyberConvoyScout',0,0,1,'CyberConvoyScout','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(18,'infrawatch','Infrawatch',0,0,1,'Infrawatch','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(19,'flowiq-labs','FlowIQ Labs',0,0,1,'FlowIQ','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(20,'visionheight','visionheight',0,0,1,'visionheight','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(21,'cortex-xpanse-palo-alto','Cortex Xpanse (Palo Alto)',0,0,1,'Cortex-Xpanse','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(22,'securityscanner','SecurityScanner',0,0,1,'SecurityScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(23,'exposurescanner','ExposureScanner',0,0,1,'ExposureScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(24,'exposurewatch','ExposureWatch',0,0,1,'ExposureWatch','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(25,'modatscanner','ModatScanner',0,0,1,'ModatScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(26,'sofyabot','SofyaBot',0,0,1,'SofyaBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(27,'umai-scanner','Umai-Scanner',0,0,1,'Umai-Scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(28,'jscrawler','jscrawler',0,0,1,'jscrawler','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(29,'cms-checker','CMS-Checker',0,0,1,'CMS-Checker','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(30,'freepbx-scanner','FreePBX-Scanner',0,0,1,'FreePBX-Scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(31,'foda-scanner','foda-scanner',0,0,1,'foda-scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(32,'fastsourcescanner','FastSourceScanner',0,0,1,'FastSourceScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(33,'smartermail-scanner','SmarterMail-Scanner',0,0,1,'SmarterMail-Scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(34,'goscanner','GoScanner',0,0,1,'GoScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(35,'nextscanner','NextScanner',0,0,1,'nextscan','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(36,'wp-safe-scanner','WP-Safe-Scanner',0,0,1,'WP-Safe-Scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(37,'ct-wp-scanner','CT-WP-Scanner',0,0,1,'CT-WP-Scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(38,'argusscanner','ArgusScanner',0,0,1,'ArgusScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(39,'agentreadinessscanner','AgentReadinessScanner',0,0,1,'AgentReadinessScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(40,'zmap-proxy-probe','zmap-proxy-probe',0,0,1,'zmap-proxy-probe','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(41,'tchelebi','tchelebi',0,0,1,'tchelebi','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(42,'l9tcpid','l9tcpid',0,0,1,'l9tcpid','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(43,'rootevidence','RootEvidence',0,0,1,'RootEvidence','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(44,'vuln-scanner','vuln_scanner',0,0,1,'vuln_scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(45,'recordedfuture-inventory','RecordedFuture Inventory',0,0,1,'RecordedFuture','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(46,'l9explore','L9explore',0,0,1,'l9explore','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(47,'ipip-crawler','Ipip Crawler',0,0,1,'HTTP Banner Detection','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(48,'bitsight-crawler','Bitsight Crawler',0,0,1,'BitSightBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(49,'feroxbuster','feroxbuster',0,0,1,'feroxbuster','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(50,'research-scan','research-scan',0,0,1,'research-scan','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(51,'securityresearch','SecurityResearch',0,0,1,'SecurityResearch','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(52,'netscope-security-research-scanner','NetScope security research scanner',0,0,1,'security research scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(53,'yokohama-institute-of-information-security','Yokohama Institute of Information Security',0,0,1,'iisec.ac.jp','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(54,'helloscan','HelloScan',0,0,1,'HelloScan','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(55,'vitesweep','vitesweep',0,0,1,'vitesweep','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(56,'proximity-sweep','proximity-sweep',0,0,1,'proximity-sweep','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(57,'securityaudit','SecurityAudit',0,0,1,'SecurityAudit','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(58,'vuln-audit','VULN-Audit',0,0,1,'VULN-Audit','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(59,'rawgrab','rawgrab',0,0,1,'rawgrab','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(60,'keydrop-onlyscans-com','Keydrop (onlyscans.com)',0,0,1,'Keydrop','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(61,'cms-detector','CMS-Detector',0,0,1,'CMS-Detector','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(62,'cms-scanner','CMS-Scanner',0,0,1,'CMS-Scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(63,'aiscan','AIScan',0,0,1,'AIScan','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(64,'tttx-net-research-scan','tttx.net research scan',0,0,1,'tttx.net','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(65,'zern-scanner','zern-scanner',0,0,1,'zern-scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(66,'scanproxy','ScanProxy',0,0,1,'ScanProxy','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(67,'highperfscanner','HighPerfScanner',0,0,1,'HighPerfScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(68,'exchangescanner','ExchangeScanner',0,0,1,'ExchangeScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(69,'wanscanner','WanScanner',0,0,1,'WanScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(70,'nextjsdetector','NextJSDetector',0,0,1,'NextJSDetector','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(71,'nextjs-scanner','nextjs-scanner',0,0,1,'nextjs-scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(72,'laraveldetector','LaravelDetector',0,0,1,'LaravelDetector','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(73,'osint-scanner','osint-scanner',0,0,1,'osint-scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(74,'wkscan','wkscan',0,0,1,'wkscan','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(75,'ipscan','ipscan',0,0,1,'ipscan','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(76,'cam-scanner','cam-scanner',0,0,1,'cam-scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(77,'rtsp-scanner','RTSP-Scanner',0,0,1,'RTSP-Scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(78,'vpn-scanner','VPN-Scanner',0,0,1,'VPN-Scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(79,'internal-scan','internal-scan',0,0,1,'internal-scan','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(80,'fingerprint-scan','fingerprint-scan',0,0,1,'fingerprint-scan','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(81,'nxploitedscanner','NxploitedScanner',0,0,1,'Nxploited','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(82,'gitscan','gitscan',0,0,1,'gitscan','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(83,'formsqliscan','FormSQLiScan',0,0,1,'SQLiScan','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(84,'botdetectorscanner','BotDetectorScanner',0,0,1,'BotDetectorScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(85,'noctrarecon','NoctraRecon',0,0,1,'NoctraRecon','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(86,'halosecurity','HaloSecurity',0,0,1,'HaloSecurity','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(87,'forestscanner','ForestScanner',0,0,1,'ForestScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(88,'atomicedge-research','AtomicEdge-Research',0,0,1,'AtomicEdge','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(89,'cloudanchor-census','CloudAnchor Census',0,0,1,'CloudAnchor','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(90,'scraped-user-agent-list','scraped user-agent list',0,0,1,'user agents strings','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(91,'serankingbacklinksbot','SERankingBacklinksBot',0,0,1,'SERankingBacklinksBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(92,'domainscores','DomainScores',0,0,1,'DomainScores','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(93,'techspybot','TechSpyBot',0,0,1,'TechSpyBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(94,'globradarbot','GlobRadarBot',0,0,1,'GlobRadarBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(95,'scalinthbot','ScalinthBot',0,0,1,'ScalinthBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(96,'forestengine','ForestEngine',0,0,1,'ForestEngine','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(97,'lohisoftbot','LohiSoftBot',0,0,1,'LohiSoftBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(98,'sleepbot','SleepBot',0,0,1,'SleepBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(99,'brokenlinksbot','BrokenLinksBot',0,0,1,'BrokenLinksBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(100,'careerpagebot','CareerPageBot',0,0,1,'CareerPageBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(101,'leadhausbot','LeadHausBot',0,0,1,'LeadHausBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(102,'imj-companypage-scraper','IMJ-CompanyPage-Scraper',0,0,1,'CompanyPage-Scraper','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(103,'seojuice','SEOJuice',0,0,1,'SEOJuice','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(104,'publicwwwbot','PublicWWWBot',0,0,1,'PublicWWWBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(105,'leak-info','leak.info',0,0,1,'leak.info','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(106,'go-web-pentest-tool','Go Web Pentest Tool',0,0,1,'Web Pentest','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(107,'envscanner','EnvScanner',0,0,1,'EnvScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(108,'exposure-scanner','Exposure-Scanner',0,0,1,'Exposure-Scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(109,'webanalyzer','WebAnalyzer',0,0,1,'WebAnalyzer','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(110,'pragmaticsecurity-scanner','PragmaticSecurity-Scanner',0,0,1,'PragmaticSecurity','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(111,'fastscan','FastScan',0,0,1,'FastScan','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(112,'ip-scanner','ip_scanner',0,0,1,'ip_scanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(113,'bgp-scan-agent','bgp-scan-agent',0,0,1,'bgp-scan','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(114,'cms-port-check','cms-port-check',0,0,1,'cms-port-check','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(115,'csscheck','CSSCheck',0,0,1,'CSSCheck','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(116,'gulper-web-bot','Gulper Web Bot',0,0,1,'GulperBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(117,'web-downloader','Web Downloader',0,0,1,'Web Downloader','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(118,'msh-pdfmin','msh-pdfmin',0,0,1,'msh-pdfmin','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(119,'proxy-checker','proxy_checker',0,0,1,'proxy_checker','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(120,'adaptive-bot','adaptive-bot',0,0,1,'adaptive-bot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(121,'nginx-loadcheck','nginx-loadcheck',0,0,1,'nginx-loadcheck','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(122,'httpheaderscheck','HTTPHeadersCheck',0,0,1,'HTTPHeadersCheck','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(123,'r00ts3c','r00ts3c',0,0,1,'r00ts3c','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(124,'gbrmss','gbrmss',0,0,1,'gbrmss','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(125,'spark-commit','SPARK COMMIT',0,0,1,'SPARK COMMIT','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(126,'linux-gnu-cow','Linux Gnu (cow)',0,0,1,'Linux Gnu','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(127,'ntrip-gnssinternetradio','NTRIP GNSSInternetRadio',0,0,1,'GNSSInternetRadio','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(128,'hello-world-with-a-comma','Hello, World (with a comma)',0,0,1,'Hello, World','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(129,'hello-world','Hello World',0,0,1,'Hello World','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(130,'globalprotect-palo-alto','GlobalProtect (Palo Alto)',0,0,1,'PAN GlobalProtect','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(131,'what-vpn','what-vpn',0,0,1,'what-vpn','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(132,'pulse-secure-ncsrv','Pulse Secure ncsrv',0,0,1,'ncsrv','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(133,'microsoft-winrm-client','Microsoft WinRM Client',0,0,1,'WinRM Client','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(134,'ciscosslvpnscanner','CiscoSSLVPNScanner',0,0,1,'CiscoSSLVPNScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(135,'ciscoscanner','CiscoScanner',0,0,1,'CiscoScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(136,'milesight-sms-scanner','Milesight SMS Scanner',0,0,1,'Milesight','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(137,'mistralbot-impersonated','MistralBot (impersonated)',0,0,1,'MistralBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(138,'coherebot-impersonated','CohereBot (impersonated)',0,0,1,'CohereBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(139,'software-security-research-rub','Software Security Research (RUB)',0,0,1,'Software Security Research','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(140,'ku-leuven-dns-renewal-study','KU Leuven DNS renewal study',0,0,1,'DNSRenewal-Study','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(141,'datafoundationresearch','DataFoundationResearch',0,0,1,'DataFoundationResearch','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(142,'nufounders-lead-research','NuFounders lead research',0,0,1,'NuFoundersLeadResearch','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(143,'newsletterformresearchbot','NewsletterFormResearchBot',0,0,1,'NewsletterFormResearch','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(144,'measureboardresearchbot','MeasureboardResearchBot',0,0,1,'MeasureboardResearch','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(145,'tokenaderesearchbot','TokenadeResearchBot',0,0,1,'TokenadeResearch','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(146,'understory-ct-research','understory CT research',0,0,1,'understory','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(147,'darkalgo-research','darkalgo-research',0,0,1,'darkalgo-research','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(148,'metaphor-data-pipeline','metaphor-data-pipeline',0,0,1,'metaphor-data-pipeline','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(149,'sponsorsearch-validation','sponsorsearch-validation',0,0,1,'sponsorsearch-validation','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(150,'bearblog-outreach','bearblog-outreach',0,0,1,'bearblog-outreach','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(151,'peers-researcher-index','peers-researcher-index',0,0,1,'peers-researcher-index','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(152,'website-analysis','website-analysis',0,0,1,'website-analysis','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(153,'qlyzebot','QlyzeBot',0,0,1,'QlyzeBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(154,'stumblebot','StumbleBot',0,0,1,'StumbleBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(155,'emanagerbot','eManagerBot',0,0,1,'eManagerBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(156,'netsurferbot','NetsurferBot',0,0,1,'NetsurferBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(157,'pisarbot','PisarBot',0,0,1,'PisarBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(158,'apcosysbot','ApcosysBot',0,0,1,'ApcosysBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(159,'ironfountain-leads','IronFountain Leads',0,0,1,'IronFountain','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(160,'sonarprime-redirectmap','SonarPrime RedirectMap',0,0,1,'SonarPrime','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(161,'saasbrowserbot','SaaSBrowserBot',0,0,1,'SaaSBrowserBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(162,'netapi','NetAPI',0,0,1,'netapi.com','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(163,'webatlabot','WebatlaBot',0,0,1,'WebatlaBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(164,'plytikbot','PlytikBot',0,0,1,'PlytikBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(165,'osentix-crawler','osentix-crawler',0,0,1,'osentix','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(166,'opr-crawler','opr-crawler',0,0,1,'opr-crawler','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(167,'fossickbot','FossickBot',0,0,1,'FossickBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(168,'rankpulsebot','RankPulseBot',0,0,1,'RankPulseBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(169,'metodasearchbot','MetodaSearchBot',0,0,1,'MetodaSearchBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(170,'getdomaindata','getdomaindata',0,0,1,'getdomaindata','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(171,'mentodomainaudit','MentoDomainAudit',0,0,1,'MentoDomainAudit','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(172,'domainsignalaudit','DomainSignalAudit',0,0,1,'DomainSignalAudit','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(173,'wordpresspostchecker','WordPressPostChecker',0,0,1,'WordPressPostChecker','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(174,'huaweicrawler','HuaweiCrawler',0,0,1,'HuaweiCrawler','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(175,'besacrawler','BesaCrawler',0,0,1,'BesaCrawler','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(176,'rootcrawl','RootCrawl',0,0,1,'RootCrawl','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(177,'txtbot','txtbot',0,0,1,'txtbot.net','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(178,'hunt-bot','HUNT-Bot',0,0,1,'HUNT-Bot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(179,'br-crawler','br-crawler',0,0,1,'br-crawler','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(180,'ucp-crawler','ucp-crawler',0,0,1,'ucp-crawler','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(181,'observer-obsrvr-net','Observer (obsrvr.net)',0,0,1,'obsrvr.net','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(182,'webrevivebot','WebReviveBot',0,0,1,'WebReviveBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(183,'form-pilot-classifier','form-pilot-classifier',0,0,1,'form-pilot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(184,'assetcheck','AssetCheck',0,0,1,'AssetCheck','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(185,'http-vs-https-checker','http-vs-https-checker',0,0,1,'http-vs-https','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(186,'public-homepage-check','public-homepage-check',0,0,1,'public-homepage-check','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(187,'smallweb-check','smallweb-check',0,0,1,'smallweb-check','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(188,'adsnexusbot','AdsNexusBot',0,0,1,'AdsNexusBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(189,'adstxtbot','AdsTxtBot',0,0,1,'AdsTxtBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(190,'ads-txt-crawler','ads-txt-crawler',0,0,1,'ads-txt-crawler','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(191,'app-ads-crawler','app-ads-crawler',0,0,1,'app-ads-crawler','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(192,'adscan','adscan',0,0,1,'adscan','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(193,'yacy-crawler','YaCy crawler',0,1,0,'yacycrawler','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(194,'camerascanner','CameraScanner',0,0,1,'CameraScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(195,'vantageresearchscanner','VantageResearchScanner',0,0,1,'VantageResearchScanner','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(196,'scanfleet','scanfleet',0,0,1,'scanfleet','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(197,'authorized-exposure-audit','authorized-exposure-audit',0,0,1,'exposure-audit','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(198,'defaultsexposed','DefaultsExposed',0,0,1,'DefaultsExposed','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(199,'statamic-lead-research','statamic-lead-research',0,0,1,'statamic-lead-research','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(200,'cold-email-radar','cold-email-radar',0,0,1,'cold-email-radar','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(201,'hackerrepos','HackerRepos',0,0,1,'HackerRepos','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(202,'copymightbot','CopyMightBot',0,0,1,'CopyMightBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(203,'webxtrendbot','webXtrendBot',0,0,1,'webXtrendBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(204,'wpdirectorybot','WPDirectoryBot',0,0,1,'WPDirectoryBot','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(205,'scrape-central','scrape_central',0,0,1,'scrape_central','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(206,'reacon-technology-worker','Reacon-Technology-Worker',0,0,1,'Reacon-Technology','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(207,'goodbot-sh','goodbot.sh',0,0,1,'goodbot.sh','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(208,'terncrawler','TernCrawler',1,0,0,'TernCrawler','default','stop-bots-extras',1794330854);
INSERT INTO bots VALUES(209,'chrome-privacy-preserving-prefetch-proxy','Chrome Privacy Preserving Prefetch Proxy',0,0,0,'Privacy Preserving Prefetch Proxy','default','stop-bots-extras',1794330854);
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
INSERT INTO bot_source_entries VALUES('trailing-backslash-bot','well-known-bots','Trailing Backslash Bot',1,0,0,'Trailing\\');
INSERT INTO bot_source_entries VALUES('let-s-encrypt-validation','stop-bots-extras','Let''s Encrypt validation',0,0,0,'Let''s Encrypt');
INSERT INTO bot_source_entries VALUES('qwantbot','stop-bots-extras','Qwantbot',0,1,0,'Qwantbot');
INSERT INTO bot_source_entries VALUES('googlebot-unversioned','stop-bots-extras','Googlebot (unversioned)',0,1,0,'Googlebot');
INSERT INTO bot_source_entries VALUES('xai-searchbot','stop-bots-extras','xAI-SearchBot',1,0,0,'xAI-SearchBot');
INSERT INTO bot_source_entries VALUES('xai-grok','stop-bots-extras','xAI-Grok',1,0,0,'xAI-Grok');
INSERT INTO bot_source_entries VALUES('grokbot','stop-bots-extras','GrokBot',1,0,0,'GrokBot');
INSERT INTO bot_source_entries VALUES('moonshotbot-kimi','stop-bots-extras','MoonshotBot (Kimi)',1,0,0,'MoonshotBot');
INSERT INTO bot_source_entries VALUES('hunyuan-tencent','stop-bots-extras','Hunyuan (Tencent)',1,0,0,'Hunyuan');
INSERT INTO bot_source_entries VALUES('yibot-01-ai','stop-bots-extras','YiBot (01.AI)',1,0,0,'YiBot');
INSERT INTO bot_source_entries VALUES('silovik','stop-bots-extras','Silovik',0,0,1,'Silovik');
INSERT INTO bot_source_entries VALUES('pathscan','stop-bots-extras','pathscan',0,0,1,'pathscan');
INSERT INTO bot_source_entries VALUES('cyberconvoyscout','stop-bots-extras','CyberConvoyScout',0,0,1,'CyberConvoyScout');
INSERT INTO bot_source_entries VALUES('infrawatch','stop-bots-extras','Infrawatch',0,0,1,'Infrawatch');
INSERT INTO bot_source_entries VALUES('flowiq-labs','stop-bots-extras','FlowIQ Labs',0,0,1,'FlowIQ');
INSERT INTO bot_source_entries VALUES('visionheight','stop-bots-extras','visionheight',0,0,1,'visionheight');
INSERT INTO bot_source_entries VALUES('cortex-xpanse-palo-alto','stop-bots-extras','Cortex Xpanse (Palo Alto)',0,0,1,'Cortex-Xpanse');
INSERT INTO bot_source_entries VALUES('securityscanner','stop-bots-extras','SecurityScanner',0,0,1,'SecurityScanner');
INSERT INTO bot_source_entries VALUES('exposurescanner','stop-bots-extras','ExposureScanner',0,0,1,'ExposureScanner');
INSERT INTO bot_source_entries VALUES('exposurewatch','stop-bots-extras','ExposureWatch',0,0,1,'ExposureWatch');
INSERT INTO bot_source_entries VALUES('modatscanner','stop-bots-extras','ModatScanner',0,0,1,'ModatScanner');
INSERT INTO bot_source_entries VALUES('sofyabot','stop-bots-extras','SofyaBot',0,0,1,'SofyaBot');
INSERT INTO bot_source_entries VALUES('umai-scanner','stop-bots-extras','Umai-Scanner',0,0,1,'Umai-Scanner');
INSERT INTO bot_source_entries VALUES('jscrawler','stop-bots-extras','jscrawler',0,0,1,'jscrawler');
INSERT INTO bot_source_entries VALUES('cms-checker','stop-bots-extras','CMS-Checker',0,0,1,'CMS-Checker');
INSERT INTO bot_source_entries VALUES('freepbx-scanner','stop-bots-extras','FreePBX-Scanner',0,0,1,'FreePBX-Scanner');
INSERT INTO bot_source_entries VALUES('foda-scanner','stop-bots-extras','foda-scanner',0,0,1,'foda-scanner');
INSERT INTO bot_source_entries VALUES('fastsourcescanner','stop-bots-extras','FastSourceScanner',0,0,1,'FastSourceScanner');
INSERT INTO bot_source_entries VALUES('smartermail-scanner','stop-bots-extras','SmarterMail-Scanner',0,0,1,'SmarterMail-Scanner');
INSERT INTO bot_source_entries VALUES('goscanner','stop-bots-extras','GoScanner',0,0,1,'GoScanner');
INSERT INTO bot_source_entries VALUES('nextscanner','stop-bots-extras','NextScanner',0,0,1,'nextscan');
INSERT INTO bot_source_entries VALUES('wp-safe-scanner','stop-bots-extras','WP-Safe-Scanner',0,0,1,'WP-Safe-Scanner');
INSERT INTO bot_source_entries VALUES('ct-wp-scanner','stop-bots-extras','CT-WP-Scanner',0,0,1,'CT-WP-Scanner');
INSERT INTO bot_source_entries VALUES('argusscanner','stop-bots-extras','ArgusScanner',0,0,1,'ArgusScanner');
INSERT INTO bot_source_entries VALUES('agentreadinessscanner','stop-bots-extras','AgentReadinessScanner',0,0,1,'AgentReadinessScanner');
INSERT INTO bot_source_entries VALUES('zmap-proxy-probe','stop-bots-extras','zmap-proxy-probe',0,0,1,'zmap-proxy-probe');
INSERT INTO bot_source_entries VALUES('tchelebi','stop-bots-extras','tchelebi',0,0,1,'tchelebi');
INSERT INTO bot_source_entries VALUES('l9tcpid','stop-bots-extras','l9tcpid',0,0,1,'l9tcpid');
INSERT INTO bot_source_entries VALUES('rootevidence','stop-bots-extras','RootEvidence',0,0,1,'RootEvidence');
INSERT INTO bot_source_entries VALUES('vuln-scanner','stop-bots-extras','vuln_scanner',0,0,1,'vuln_scanner');
INSERT INTO bot_source_entries VALUES('recordedfuture-inventory','stop-bots-extras','RecordedFuture Inventory',0,0,1,'RecordedFuture');
INSERT INTO bot_source_entries VALUES('l9explore','stop-bots-extras','L9explore',0,0,1,'l9explore');
INSERT INTO bot_source_entries VALUES('ipip-crawler','stop-bots-extras','Ipip Crawler',0,0,1,'HTTP Banner Detection');
INSERT INTO bot_source_entries VALUES('bitsight-crawler','stop-bots-extras','Bitsight Crawler',0,0,1,'BitSightBot');
INSERT INTO bot_source_entries VALUES('feroxbuster','stop-bots-extras','feroxbuster',0,0,1,'feroxbuster');
INSERT INTO bot_source_entries VALUES('research-scan','stop-bots-extras','research-scan',0,0,1,'research-scan');
INSERT INTO bot_source_entries VALUES('securityresearch','stop-bots-extras','SecurityResearch',0,0,1,'SecurityResearch');
INSERT INTO bot_source_entries VALUES('netscope-security-research-scanner','stop-bots-extras','NetScope security research scanner',0,0,1,'security research scanner');
INSERT INTO bot_source_entries VALUES('yokohama-institute-of-information-security','stop-bots-extras','Yokohama Institute of Information Security',0,0,1,'iisec.ac.jp');
INSERT INTO bot_source_entries VALUES('helloscan','stop-bots-extras','HelloScan',0,0,1,'HelloScan');
INSERT INTO bot_source_entries VALUES('vitesweep','stop-bots-extras','vitesweep',0,0,1,'vitesweep');
INSERT INTO bot_source_entries VALUES('proximity-sweep','stop-bots-extras','proximity-sweep',0,0,1,'proximity-sweep');
INSERT INTO bot_source_entries VALUES('securityaudit','stop-bots-extras','SecurityAudit',0,0,1,'SecurityAudit');
INSERT INTO bot_source_entries VALUES('vuln-audit','stop-bots-extras','VULN-Audit',0,0,1,'VULN-Audit');
INSERT INTO bot_source_entries VALUES('rawgrab','stop-bots-extras','rawgrab',0,0,1,'rawgrab');
INSERT INTO bot_source_entries VALUES('keydrop-onlyscans-com','stop-bots-extras','Keydrop (onlyscans.com)',0,0,1,'Keydrop');
INSERT INTO bot_source_entries VALUES('cms-detector','stop-bots-extras','CMS-Detector',0,0,1,'CMS-Detector');
INSERT INTO bot_source_entries VALUES('cms-scanner','stop-bots-extras','CMS-Scanner',0,0,1,'CMS-Scanner');
INSERT INTO bot_source_entries VALUES('aiscan','stop-bots-extras','AIScan',0,0,1,'AIScan');
INSERT INTO bot_source_entries VALUES('tttx-net-research-scan','stop-bots-extras','tttx.net research scan',0,0,1,'tttx.net');
INSERT INTO bot_source_entries VALUES('zern-scanner','stop-bots-extras','zern-scanner',0,0,1,'zern-scanner');
INSERT INTO bot_source_entries VALUES('scanproxy','stop-bots-extras','ScanProxy',0,0,1,'ScanProxy');
INSERT INTO bot_source_entries VALUES('highperfscanner','stop-bots-extras','HighPerfScanner',0,0,1,'HighPerfScanner');
INSERT INTO bot_source_entries VALUES('exchangescanner','stop-bots-extras','ExchangeScanner',0,0,1,'ExchangeScanner');
INSERT INTO bot_source_entries VALUES('wanscanner','stop-bots-extras','WanScanner',0,0,1,'WanScanner');
INSERT INTO bot_source_entries VALUES('nextjsdetector','stop-bots-extras','NextJSDetector',0,0,1,'NextJSDetector');
INSERT INTO bot_source_entries VALUES('nextjs-scanner','stop-bots-extras','nextjs-scanner',0,0,1,'nextjs-scanner');
INSERT INTO bot_source_entries VALUES('laraveldetector','stop-bots-extras','LaravelDetector',0,0,1,'LaravelDetector');
INSERT INTO bot_source_entries VALUES('osint-scanner','stop-bots-extras','osint-scanner',0,0,1,'osint-scanner');
INSERT INTO bot_source_entries VALUES('wkscan','stop-bots-extras','wkscan',0,0,1,'wkscan');
INSERT INTO bot_source_entries VALUES('ipscan','stop-bots-extras','ipscan',0,0,1,'ipscan');
INSERT INTO bot_source_entries VALUES('cam-scanner','stop-bots-extras','cam-scanner',0,0,1,'cam-scanner');
INSERT INTO bot_source_entries VALUES('rtsp-scanner','stop-bots-extras','RTSP-Scanner',0,0,1,'RTSP-Scanner');
INSERT INTO bot_source_entries VALUES('vpn-scanner','stop-bots-extras','VPN-Scanner',0,0,1,'VPN-Scanner');
INSERT INTO bot_source_entries VALUES('internal-scan','stop-bots-extras','internal-scan',0,0,1,'internal-scan');
INSERT INTO bot_source_entries VALUES('fingerprint-scan','stop-bots-extras','fingerprint-scan',0,0,1,'fingerprint-scan');
INSERT INTO bot_source_entries VALUES('nxploitedscanner','stop-bots-extras','NxploitedScanner',0,0,1,'Nxploited');
INSERT INTO bot_source_entries VALUES('gitscan','stop-bots-extras','gitscan',0,0,1,'gitscan');
INSERT INTO bot_source_entries VALUES('formsqliscan','stop-bots-extras','FormSQLiScan',0,0,1,'SQLiScan');
INSERT INTO bot_source_entries VALUES('botdetectorscanner','stop-bots-extras','BotDetectorScanner',0,0,1,'BotDetectorScanner');
INSERT INTO bot_source_entries VALUES('noctrarecon','stop-bots-extras','NoctraRecon',0,0,1,'NoctraRecon');
INSERT INTO bot_source_entries VALUES('halosecurity','stop-bots-extras','HaloSecurity',0,0,1,'HaloSecurity');
INSERT INTO bot_source_entries VALUES('forestscanner','stop-bots-extras','ForestScanner',0,0,1,'ForestScanner');
INSERT INTO bot_source_entries VALUES('atomicedge-research','stop-bots-extras','AtomicEdge-Research',0,0,1,'AtomicEdge');
INSERT INTO bot_source_entries VALUES('cloudanchor-census','stop-bots-extras','CloudAnchor Census',0,0,1,'CloudAnchor');
INSERT INTO bot_source_entries VALUES('scraped-user-agent-list','stop-bots-extras','scraped user-agent list',0,0,1,'user agents strings');
INSERT INTO bot_source_entries VALUES('serankingbacklinksbot','stop-bots-extras','SERankingBacklinksBot',0,0,1,'SERankingBacklinksBot');
INSERT INTO bot_source_entries VALUES('domainscores','stop-bots-extras','DomainScores',0,0,1,'DomainScores');
INSERT INTO bot_source_entries VALUES('techspybot','stop-bots-extras','TechSpyBot',0,0,1,'TechSpyBot');
INSERT INTO bot_source_entries VALUES('globradarbot','stop-bots-extras','GlobRadarBot',0,0,1,'GlobRadarBot');
INSERT INTO bot_source_entries VALUES('scalinthbot','stop-bots-extras','ScalinthBot',0,0,1,'ScalinthBot');
INSERT INTO bot_source_entries VALUES('forestengine','stop-bots-extras','ForestEngine',0,0,1,'ForestEngine');
INSERT INTO bot_source_entries VALUES('lohisoftbot','stop-bots-extras','LohiSoftBot',0,0,1,'LohiSoftBot');
INSERT INTO bot_source_entries VALUES('sleepbot','stop-bots-extras','SleepBot',0,0,1,'SleepBot');
INSERT INTO bot_source_entries VALUES('brokenlinksbot','stop-bots-extras','BrokenLinksBot',0,0,1,'BrokenLinksBot');
INSERT INTO bot_source_entries VALUES('careerpagebot','stop-bots-extras','CareerPageBot',0,0,1,'CareerPageBot');
INSERT INTO bot_source_entries VALUES('leadhausbot','stop-bots-extras','LeadHausBot',0,0,1,'LeadHausBot');
INSERT INTO bot_source_entries VALUES('imj-companypage-scraper','stop-bots-extras','IMJ-CompanyPage-Scraper',0,0,1,'CompanyPage-Scraper');
INSERT INTO bot_source_entries VALUES('seojuice','stop-bots-extras','SEOJuice',0,0,1,'SEOJuice');
INSERT INTO bot_source_entries VALUES('publicwwwbot','stop-bots-extras','PublicWWWBot',0,0,1,'PublicWWWBot');
INSERT INTO bot_source_entries VALUES('leak-info','stop-bots-extras','leak.info',0,0,1,'leak.info');
INSERT INTO bot_source_entries VALUES('go-web-pentest-tool','stop-bots-extras','Go Web Pentest Tool',0,0,1,'Web Pentest');
INSERT INTO bot_source_entries VALUES('envscanner','stop-bots-extras','EnvScanner',0,0,1,'EnvScanner');
INSERT INTO bot_source_entries VALUES('exposure-scanner','stop-bots-extras','Exposure-Scanner',0,0,1,'Exposure-Scanner');
INSERT INTO bot_source_entries VALUES('webanalyzer','stop-bots-extras','WebAnalyzer',0,0,1,'WebAnalyzer');
INSERT INTO bot_source_entries VALUES('pragmaticsecurity-scanner','stop-bots-extras','PragmaticSecurity-Scanner',0,0,1,'PragmaticSecurity');
INSERT INTO bot_source_entries VALUES('fastscan','stop-bots-extras','FastScan',0,0,1,'FastScan');
INSERT INTO bot_source_entries VALUES('ip-scanner','stop-bots-extras','ip_scanner',0,0,1,'ip_scanner');
INSERT INTO bot_source_entries VALUES('bgp-scan-agent','stop-bots-extras','bgp-scan-agent',0,0,1,'bgp-scan');
INSERT INTO bot_source_entries VALUES('cms-port-check','stop-bots-extras','cms-port-check',0,0,1,'cms-port-check');
INSERT INTO bot_source_entries VALUES('csscheck','stop-bots-extras','CSSCheck',0,0,1,'CSSCheck');
INSERT INTO bot_source_entries VALUES('gulper-web-bot','stop-bots-extras','Gulper Web Bot',0,0,1,'GulperBot');
INSERT INTO bot_source_entries VALUES('web-downloader','stop-bots-extras','Web Downloader',0,0,1,'Web Downloader');
INSERT INTO bot_source_entries VALUES('msh-pdfmin','stop-bots-extras','msh-pdfmin',0,0,1,'msh-pdfmin');
INSERT INTO bot_source_entries VALUES('proxy-checker','stop-bots-extras','proxy_checker',0,0,1,'proxy_checker');
INSERT INTO bot_source_entries VALUES('adaptive-bot','stop-bots-extras','adaptive-bot',0,0,1,'adaptive-bot');
INSERT INTO bot_source_entries VALUES('nginx-loadcheck','stop-bots-extras','nginx-loadcheck',0,0,1,'nginx-loadcheck');
INSERT INTO bot_source_entries VALUES('httpheaderscheck','stop-bots-extras','HTTPHeadersCheck',0,0,1,'HTTPHeadersCheck');
INSERT INTO bot_source_entries VALUES('r00ts3c','stop-bots-extras','r00ts3c',0,0,1,'r00ts3c');
INSERT INTO bot_source_entries VALUES('gbrmss','stop-bots-extras','gbrmss',0,0,1,'gbrmss');
INSERT INTO bot_source_entries VALUES('spark-commit','stop-bots-extras','SPARK COMMIT',0,0,1,'SPARK COMMIT');
INSERT INTO bot_source_entries VALUES('linux-gnu-cow','stop-bots-extras','Linux Gnu (cow)',0,0,1,'Linux Gnu');
INSERT INTO bot_source_entries VALUES('ntrip-gnssinternetradio','stop-bots-extras','NTRIP GNSSInternetRadio',0,0,1,'GNSSInternetRadio');
INSERT INTO bot_source_entries VALUES('hello-world-with-a-comma','stop-bots-extras','Hello, World (with a comma)',0,0,1,'Hello, World');
INSERT INTO bot_source_entries VALUES('hello-world','stop-bots-extras','Hello World',0,0,1,'Hello World');
INSERT INTO bot_source_entries VALUES('globalprotect-palo-alto','stop-bots-extras','GlobalProtect (Palo Alto)',0,0,1,'PAN GlobalProtect');
INSERT INTO bot_source_entries VALUES('what-vpn','stop-bots-extras','what-vpn',0,0,1,'what-vpn');
INSERT INTO bot_source_entries VALUES('pulse-secure-ncsrv','stop-bots-extras','Pulse Secure ncsrv',0,0,1,'ncsrv');
INSERT INTO bot_source_entries VALUES('microsoft-winrm-client','stop-bots-extras','Microsoft WinRM Client',0,0,1,'WinRM Client');
INSERT INTO bot_source_entries VALUES('ciscosslvpnscanner','stop-bots-extras','CiscoSSLVPNScanner',0,0,1,'CiscoSSLVPNScanner');
INSERT INTO bot_source_entries VALUES('ciscoscanner','stop-bots-extras','CiscoScanner',0,0,1,'CiscoScanner');
INSERT INTO bot_source_entries VALUES('milesight-sms-scanner','stop-bots-extras','Milesight SMS Scanner',0,0,1,'Milesight');
INSERT INTO bot_source_entries VALUES('mistralbot-impersonated','stop-bots-extras','MistralBot (impersonated)',0,0,1,'MistralBot');
INSERT INTO bot_source_entries VALUES('coherebot-impersonated','stop-bots-extras','CohereBot (impersonated)',0,0,1,'CohereBot');
INSERT INTO bot_source_entries VALUES('software-security-research-rub','stop-bots-extras','Software Security Research (RUB)',0,0,1,'Software Security Research');
INSERT INTO bot_source_entries VALUES('ku-leuven-dns-renewal-study','stop-bots-extras','KU Leuven DNS renewal study',0,0,1,'DNSRenewal-Study');
INSERT INTO bot_source_entries VALUES('datafoundationresearch','stop-bots-extras','DataFoundationResearch',0,0,1,'DataFoundationResearch');
INSERT INTO bot_source_entries VALUES('nufounders-lead-research','stop-bots-extras','NuFounders lead research',0,0,1,'NuFoundersLeadResearch');
INSERT INTO bot_source_entries VALUES('newsletterformresearchbot','stop-bots-extras','NewsletterFormResearchBot',0,0,1,'NewsletterFormResearch');
INSERT INTO bot_source_entries VALUES('measureboardresearchbot','stop-bots-extras','MeasureboardResearchBot',0,0,1,'MeasureboardResearch');
INSERT INTO bot_source_entries VALUES('tokenaderesearchbot','stop-bots-extras','TokenadeResearchBot',0,0,1,'TokenadeResearch');
INSERT INTO bot_source_entries VALUES('understory-ct-research','stop-bots-extras','understory CT research',0,0,1,'understory');
INSERT INTO bot_source_entries VALUES('darkalgo-research','stop-bots-extras','darkalgo-research',0,0,1,'darkalgo-research');
INSERT INTO bot_source_entries VALUES('metaphor-data-pipeline','stop-bots-extras','metaphor-data-pipeline',0,0,1,'metaphor-data-pipeline');
INSERT INTO bot_source_entries VALUES('sponsorsearch-validation','stop-bots-extras','sponsorsearch-validation',0,0,1,'sponsorsearch-validation');
INSERT INTO bot_source_entries VALUES('bearblog-outreach','stop-bots-extras','bearblog-outreach',0,0,1,'bearblog-outreach');
INSERT INTO bot_source_entries VALUES('peers-researcher-index','stop-bots-extras','peers-researcher-index',0,0,1,'peers-researcher-index');
INSERT INTO bot_source_entries VALUES('website-analysis','stop-bots-extras','website-analysis',0,0,1,'website-analysis');
INSERT INTO bot_source_entries VALUES('qlyzebot','stop-bots-extras','QlyzeBot',0,0,1,'QlyzeBot');
INSERT INTO bot_source_entries VALUES('stumblebot','stop-bots-extras','StumbleBot',0,0,1,'StumbleBot');
INSERT INTO bot_source_entries VALUES('emanagerbot','stop-bots-extras','eManagerBot',0,0,1,'eManagerBot');
INSERT INTO bot_source_entries VALUES('netsurferbot','stop-bots-extras','NetsurferBot',0,0,1,'NetsurferBot');
INSERT INTO bot_source_entries VALUES('pisarbot','stop-bots-extras','PisarBot',0,0,1,'PisarBot');
INSERT INTO bot_source_entries VALUES('apcosysbot','stop-bots-extras','ApcosysBot',0,0,1,'ApcosysBot');
INSERT INTO bot_source_entries VALUES('ironfountain-leads','stop-bots-extras','IronFountain Leads',0,0,1,'IronFountain');
INSERT INTO bot_source_entries VALUES('sonarprime-redirectmap','stop-bots-extras','SonarPrime RedirectMap',0,0,1,'SonarPrime');
INSERT INTO bot_source_entries VALUES('saasbrowserbot','stop-bots-extras','SaaSBrowserBot',0,0,1,'SaaSBrowserBot');
INSERT INTO bot_source_entries VALUES('netapi','stop-bots-extras','NetAPI',0,0,1,'netapi.com');
INSERT INTO bot_source_entries VALUES('webatlabot','stop-bots-extras','WebatlaBot',0,0,1,'WebatlaBot');
INSERT INTO bot_source_entries VALUES('plytikbot','stop-bots-extras','PlytikBot',0,0,1,'PlytikBot');
INSERT INTO bot_source_entries VALUES('osentix-crawler','stop-bots-extras','osentix-crawler',0,0,1,'osentix');
INSERT INTO bot_source_entries VALUES('opr-crawler','stop-bots-extras','opr-crawler',0,0,1,'opr-crawler');
INSERT INTO bot_source_entries VALUES('fossickbot','stop-bots-extras','FossickBot',0,0,1,'FossickBot');
INSERT INTO bot_source_entries VALUES('rankpulsebot','stop-bots-extras','RankPulseBot',0,0,1,'RankPulseBot');
INSERT INTO bot_source_entries VALUES('metodasearchbot','stop-bots-extras','MetodaSearchBot',0,0,1,'MetodaSearchBot');
INSERT INTO bot_source_entries VALUES('getdomaindata','stop-bots-extras','getdomaindata',0,0,1,'getdomaindata');
INSERT INTO bot_source_entries VALUES('mentodomainaudit','stop-bots-extras','MentoDomainAudit',0,0,1,'MentoDomainAudit');
INSERT INTO bot_source_entries VALUES('domainsignalaudit','stop-bots-extras','DomainSignalAudit',0,0,1,'DomainSignalAudit');
INSERT INTO bot_source_entries VALUES('wordpresspostchecker','stop-bots-extras','WordPressPostChecker',0,0,1,'WordPressPostChecker');
INSERT INTO bot_source_entries VALUES('huaweicrawler','stop-bots-extras','HuaweiCrawler',0,0,1,'HuaweiCrawler');
INSERT INTO bot_source_entries VALUES('besacrawler','stop-bots-extras','BesaCrawler',0,0,1,'BesaCrawler');
INSERT INTO bot_source_entries VALUES('rootcrawl','stop-bots-extras','RootCrawl',0,0,1,'RootCrawl');
INSERT INTO bot_source_entries VALUES('txtbot','stop-bots-extras','txtbot',0,0,1,'txtbot.net');
INSERT INTO bot_source_entries VALUES('hunt-bot','stop-bots-extras','HUNT-Bot',0,0,1,'HUNT-Bot');
INSERT INTO bot_source_entries VALUES('br-crawler','stop-bots-extras','br-crawler',0,0,1,'br-crawler');
INSERT INTO bot_source_entries VALUES('ucp-crawler','stop-bots-extras','ucp-crawler',0,0,1,'ucp-crawler');
INSERT INTO bot_source_entries VALUES('observer-obsrvr-net','stop-bots-extras','Observer (obsrvr.net)',0,0,1,'obsrvr.net');
INSERT INTO bot_source_entries VALUES('webrevivebot','stop-bots-extras','WebReviveBot',0,0,1,'WebReviveBot');
INSERT INTO bot_source_entries VALUES('form-pilot-classifier','stop-bots-extras','form-pilot-classifier',0,0,1,'form-pilot');
INSERT INTO bot_source_entries VALUES('assetcheck','stop-bots-extras','AssetCheck',0,0,1,'AssetCheck');
INSERT INTO bot_source_entries VALUES('http-vs-https-checker','stop-bots-extras','http-vs-https-checker',0,0,1,'http-vs-https');
INSERT INTO bot_source_entries VALUES('public-homepage-check','stop-bots-extras','public-homepage-check',0,0,1,'public-homepage-check');
INSERT INTO bot_source_entries VALUES('smallweb-check','stop-bots-extras','smallweb-check',0,0,1,'smallweb-check');
INSERT INTO bot_source_entries VALUES('adsnexusbot','stop-bots-extras','AdsNexusBot',0,0,1,'AdsNexusBot');
INSERT INTO bot_source_entries VALUES('adstxtbot','stop-bots-extras','AdsTxtBot',0,0,1,'AdsTxtBot');
INSERT INTO bot_source_entries VALUES('ads-txt-crawler','stop-bots-extras','ads-txt-crawler',0,0,1,'ads-txt-crawler');
INSERT INTO bot_source_entries VALUES('app-ads-crawler','stop-bots-extras','app-ads-crawler',0,0,1,'app-ads-crawler');
INSERT INTO bot_source_entries VALUES('adscan','stop-bots-extras','adscan',0,0,1,'adscan');
INSERT INTO bot_source_entries VALUES('yacy-crawler','stop-bots-extras','YaCy crawler',0,1,0,'yacycrawler');
INSERT INTO bot_source_entries VALUES('camerascanner','stop-bots-extras','CameraScanner',0,0,1,'CameraScanner');
INSERT INTO bot_source_entries VALUES('vantageresearchscanner','stop-bots-extras','VantageResearchScanner',0,0,1,'VantageResearchScanner');
INSERT INTO bot_source_entries VALUES('scanfleet','stop-bots-extras','scanfleet',0,0,1,'scanfleet');
INSERT INTO bot_source_entries VALUES('authorized-exposure-audit','stop-bots-extras','authorized-exposure-audit',0,0,1,'exposure-audit');
INSERT INTO bot_source_entries VALUES('defaultsexposed','stop-bots-extras','DefaultsExposed',0,0,1,'DefaultsExposed');
INSERT INTO bot_source_entries VALUES('statamic-lead-research','stop-bots-extras','statamic-lead-research',0,0,1,'statamic-lead-research');
INSERT INTO bot_source_entries VALUES('cold-email-radar','stop-bots-extras','cold-email-radar',0,0,1,'cold-email-radar');
INSERT INTO bot_source_entries VALUES('hackerrepos','stop-bots-extras','HackerRepos',0,0,1,'HackerRepos');
INSERT INTO bot_source_entries VALUES('copymightbot','stop-bots-extras','CopyMightBot',0,0,1,'CopyMightBot');
INSERT INTO bot_source_entries VALUES('webxtrendbot','stop-bots-extras','webXtrendBot',0,0,1,'webXtrendBot');
INSERT INTO bot_source_entries VALUES('wpdirectorybot','stop-bots-extras','WPDirectoryBot',0,0,1,'WPDirectoryBot');
INSERT INTO bot_source_entries VALUES('scrape-central','stop-bots-extras','scrape_central',0,0,1,'scrape_central');
INSERT INTO bot_source_entries VALUES('reacon-technology-worker','stop-bots-extras','Reacon-Technology-Worker',0,0,1,'Reacon-Technology');
INSERT INTO bot_source_entries VALUES('goodbot-sh','stop-bots-extras','goodbot.sh',0,0,1,'goodbot.sh');
INSERT INTO bot_source_entries VALUES('terncrawler','stop-bots-extras','TernCrawler',1,0,0,'TernCrawler');
INSERT INTO bot_source_entries VALUES('chrome-privacy-preserving-prefetch-proxy','stop-bots-extras','Chrome Privacy Preserving Prefetch Proxy',0,0,0,'Privacy Preserving Prefetch Proxy');
CREATE TABLE sites (
                id INTEGER PRIMARY KEY,
                server_name TEXT NOT NULL,
                config_path TEXT NOT NULL,
                discovered_at INTEGER NOT NULL,
                UNIQUE(server_name, config_path)
            );
INSERT INTO sites VALUES(1,'example.com','/etc/nginx/sites-enabled/example.com',1794330854);
CREATE TABLE settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
INSERT INTO settings VALUES('default_status_scanner','blocked');
INSERT INTO settings VALUES('default_status_search','blocked');
INSERT INTO settings VALUES('default_status_ai','blocked');
INSERT INTO settings VALUES('geo_mode','allowlist');
INSERT INTO settings VALUES('db:defaults_generation','5');
INSERT INTO settings VALUES('detect:block_web_scanners:enabled','false');
INSERT INTO settings VALUES('detect:block_asset_ratio:enabled','true');
INSERT INTO settings VALUES('detect:block_probe_paths:ttl_days','9');
INSERT INTO settings VALUES('detect_ssh_scanners_min_attempts','7');
INSERT INTO settings VALUES('detect:block_scanners:window_hours','48');
INSERT INTO settings VALUES('block_response','410');
INSERT INTO settings VALUES('serve_robots_txt','true');
INSERT INTO settings VALUES('rate_limit_rps','7');
INSERT INTO settings VALUES('rate_limit_burst','11');
INSERT INTO settings VALUES('rate_limit_enabled','true');
INSERT INTO settings VALUES('firewall:backend','nftables');
INSERT INTO settings VALUES('firewall_rendered_signature','9991038eecf88c760de4b13ad39becea47cfdfc037f9afae9c4235e40e66e7e7');
CREATE TABLE firewall_rules (
                id INTEGER PRIMARY KEY,
                address TEXT NOT NULL,
                port INTEGER,
                action TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                expires_at INTEGER
            , source TEXT, evidence TEXT);
INSERT INTO firewall_rules VALUES(1,'203.0.113.7',NULL,'block',1,1794330854,NULL,'cli',NULL);
INSERT INTO firewall_rules VALUES(2,'198.51.100.0/24',22,'block',1,1794330854,NULL,'cli',NULL);
INSERT INTO firewall_rules VALUES(3,'192.0.2.1',NULL,'allow',1,1794330854,NULL,'cli',NULL);
CREATE TABLE site_category_overrides (
                site_id INTEGER NOT NULL REFERENCES sites(id),
                category TEXT NOT NULL,
                policy TEXT NOT NULL,
                PRIMARY KEY (site_id, category)
            );
INSERT INTO site_category_overrides VALUES(1,'ai','allowed');
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
INSERT INTO selected_countries VALUES('hr',1794330854);
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
INSERT INTO trusted_addresses VALUES('192.0.2.10',1794330854);
CREATE TABLE trusted_user_agents (
                user_agent TEXT PRIMARY KEY,
                trusted_at INTEGER NOT NULL
            );
INSERT INTO trusted_user_agents VALUES('UptimeRobot',1794330854);
CREATE TABLE managed_files (
            path TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            written_at INTEGER NOT NULL,
            version TEXT NOT NULL
        );
INSERT INTO managed_files VALUES('/etc/stop-bots/nginx/robots.txt','nginx-robots-txt',1794330854,'0.11.0');
INSERT INTO managed_files VALUES('/etc/nginx/conf.d/stop-bots-trusted.conf','nginx-trusted',1794330854,'0.11.0');
INSERT INTO managed_files VALUES('/etc/nginx/conf.d/stop-bots-limits.conf','nginx-limits',1794330854,'0.11.0');
INSERT INTO managed_files VALUES('/etc/nginx/conf.d/stop-bots-limits-untrusted.conf','nginx-untrusted-limits',1794330854,'0.11.0');
CREATE TABLE log_evidence (
                detector TEXT NOT NULL,
                address TEXT NOT NULL,
                -- What was seen: a path, a user agent, a payload's kind;
                -- or, starting with a newline no log line can hold, a
                -- clearing observation or a count bucket. See
                -- `evidence::Item`.
                item TEXT NOT NULL,
                count INTEGER NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY (detector, address, item)
            );
CREATE TABLE unblocked_addresses (
             address TEXT PRIMARY KEY,
             source TEXT,
             unblocked_at INTEGER NOT NULL,
             until INTEGER NOT NULL
         );
CREATE TABLE console_logins (
             address TEXT PRIMARY KEY,
             last_login INTEGER NOT NULL
         );
CREATE TABLE remembered_browsers (
             token_hash TEXT PRIMARY KEY,
             created_at INTEGER NOT NULL,
             last_used_at INTEGER NOT NULL
         );
CREATE TABLE offences (
             address TEXT PRIMARY KEY,
             source TEXT NOT NULL,
             count INTEGER NOT NULL,
             last_offence_at INTEGER NOT NULL,
             blocked_until INTEGER NOT NULL
         );
CREATE TABLE hosting_asns (
             asn INTEGER PRIMARY KEY,
             description TEXT,
             added_at INTEGER NOT NULL,
             last_fetched_at INTEGER,
             range_count INTEGER NOT NULL DEFAULT 0
         );
CREATE TABLE hosting_asn_ranges (
             asn INTEGER NOT NULL REFERENCES hosting_asns(asn),
             cidr TEXT NOT NULL,
             PRIMARY KEY (asn, cidr)
         );
CREATE TABLE egress_feeds (
             id TEXT PRIMARY KEY,
             name TEXT NOT NULL,
             url TEXT NOT NULL,
             kind TEXT NOT NULL,
             builtin INTEGER NOT NULL,
             enabled INTEGER NOT NULL DEFAULT 0,
             contain INTEGER NOT NULL DEFAULT 0,
             last_fetched_at INTEGER,
             entry_count INTEGER NOT NULL DEFAULT 0,
             kept_off INTEGER NOT NULL DEFAULT 0
         );
CREATE TABLE egress_entries (
             feed_id TEXT NOT NULL REFERENCES egress_feeds(id),
             entry TEXT NOT NULL,
             PRIMARY KEY (feed_id, entry)
         );
CREATE TABLE egress_hits (
             id INTEGER PRIMARY KEY,
             path TEXT NOT NULL,
             source TEXT NOT NULL,
             destination TEXT NOT NULL,
             port INTEGER,
             protocol TEXT NOT NULL,
             uid INTEGER,
             count INTEGER NOT NULL,
             first_seen INTEGER NOT NULL,
             last_seen INTEGER NOT NULL,
             evidence TEXT NOT NULL,
             container_id TEXT,
             container_name TEXT,
             responded_at INTEGER
         );
CREATE TABLE containments (
             id INTEGER PRIMARY KEY,
             kind TEXT NOT NULL,
             target TEXT NOT NULL,
             name TEXT,
             addresses TEXT NOT NULL DEFAULT '',
             action TEXT NOT NULL,
             reason TEXT NOT NULL,
             automatic INTEGER NOT NULL,
             created_at INTEGER NOT NULL,
             released_at INTEGER
         );
CREATE TABLE site_waf (
             site_id INTEGER PRIMARY KEY REFERENCES sites(id),
             exploit_rules INTEGER,
             modsecurity TEXT,
             paranoia INTEGER
         );
CREATE TABLE modsecurity_exclusions (
             site_id INTEGER NOT NULL REFERENCES sites(id),
             rule_id INTEGER NOT NULL,
             path TEXT NOT NULL,
             created_at INTEGER NOT NULL,
             PRIMARY KEY (site_id, rule_id, path)
         );
CREATE INDEX log_evidence_age ON log_evidence (detector, last_seen);
CREATE INDEX log_evidence_address ON log_evidence (address);
CREATE UNIQUE INDEX firewall_rules_one_per_rule
             ON firewall_rules (address, action, IFNULL(port, -1));
CREATE INDEX firewall_rules_by_source ON firewall_rules (source);
CREATE UNIQUE INDEX egress_hits_flow ON egress_hits
             (path, source, destination, ifnull(port, -1), ifnull(uid, -1));
CREATE UNIQUE INDEX containments_open ON containments (kind, target)
             WHERE released_at IS NULL;
COMMIT;
PRAGMA user_version=10;
