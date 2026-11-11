# COTI — SIEM Detection Engineering Lab

BrightMart, a simulated medium-sized online retailer, reported odd-hour login attempts, error messages from its web store and unusual outbound connections from internal systems. This lab rebuilds that environment on three virtual machines, instruments it with Splunk Enterprise, and exercises twelve attack techniques against an OWASP Juice Shop instance. A detection search and a severity-rated alert were written for each technique, using application, Windows and network telemetry.

## Contents

| File | Description |
| --- | --- |
| `COTI-Report.docx` | Full assignment report |

## Scenario

BrightMart's management first dismissed the traffic spikes as routine faults, but customer reports of failed logins and slow responses prompted an investigation. The brief was to establish the root cause, reproduce the threats an online retailer of that size would face, and deploy detection coverage across the application, host and network layers. The storefront is mirrored with OWASP Juice Shop on Windows 10, with a Kali Linux host acting as the attacker.

## Lab environment

| Host | System | Role |
| --- | --- | --- |
| 192.168.8.130 | Windows 10, OWASP Juice Shop | Target web application; hosts the Splunk Universal Forwarder and Snort IDS |
| 192.168.8.131 | Windows Server 2012 | Splunk Enterprise indexer, receiving forwarded events on TCP 9997 |
| 192.168.8.132 | Kali Linux | Attack platform |

Splunk Enterprise indexes all telemetry, and the Universal Forwarder on 192.168.8.130 ships Juice Shop access logs, Windows Security, Windows Defender and Snort output to the indexer at 192.168.8.131.

## Detection engineering

Ingestion is file-based. `inputs.conf` on the Juice Shop host monitors `access.log` in the application's `logs/` directory and tags it `juice:access`; Windows Security is collected through `WinEventLog://Security` as `XmlWinEventLog:Security`; Snort's `sfportscan` preprocessor writes to `C:\Snort\log\portscan.log`, forwarded as `snort:portscan`; Defender Operational logs arrive under their own sourcetype. `outputs.conf` points the forwarder at the indexer on TCP 9997.

Two sources needed work before they were usable. Juice Shop is a single-page application that returns HTTP 200 for non-existent paths, so status-code detection produced only noise; enumeration is detected on request volume instead, and gobuster was tuned to exclude the 80150-byte soft-404 body. Access logs also omitted transaction parameters, so `server.js` was modified to append `basket_qty=<value>` to each entry, making negative-quantity abuse visible at the web tier at all.

Detections are scheduled searches over a 24-hour window, generally running every minute. Each keys on a specific field or encoded pattern rather than a raw string match.

| Detection | Data source | Keys on |
| --- | --- | --- |
| SQL injection | `juice:access` | Encoded quote `%27` with `%20OR%20`/`%20AND%20`, `UNION SELECT`, SQLite `randomblob`, on `/rest/products/search` and `/rest/user/login` |
| SMB abuse | `XmlWinEventLog:Security` | Event ID 4625 followed by 4624 with LogonType 3; extracts `TargetUserName`, `IpAddress`, `WorkstationName` |
| Reflected XSS | `juice:access` | `urldecode(_raw)` matched against `<iframe`, `javascript:` and `<script` on `/rest/track-order` |
| Network scanning | `snort:portscan` | `sfportscan` alerts for rapid incomplete TCP handshakes across ports 1–1000 |
| Directory enumeration | `juice:access` | `timechart count` request volume; fires above 100 results, real time |
| IDOR | `juice:access` | `dc(uri_path) >= 3` on `/rest/basket/`, grouped by `src_ip` |
| Admin endpoint access | `juice:access` | Any request to `/rest/admin/`, grouped by `src_ip` |
| Brute force | `juice:access` | `stats count by src_ip` on `/rest/user/login`, threshold 10 attempts |
| Denial of service | all indexes | `stats count as req_count by src_ip uri_path` over GET and POST, 5-minute window |
| Malware infection | Defender Operational | EventCode 1116, 1117 or 1121, counted by `ComputerName` |
| Business logic abuse | `juice:access` | `rex` on `basket_qty=` then `where basket_qty < 0` |
| CSRF | `juice:access` | `rex` on status and referrer; `/profile` requests whose referrer is not the Juice Shop origin |

Severity follows assessed impact: Critical for unauthenticated administrative endpoint access, High for SQL injection, IDOR, brute force, malware, business logic abuse, CSRF and enumeration, Medium for SMB abuse, reflected XSS and denial of service.

## Attack scenarios exercised

| Scenario | Technique | Observed result |
| --- | --- | --- |
| SQL injection | Manual `' OR 1=1--` login bypass, boolean payloads on product search, then sqlmap at level 5 / risk 3 | Login bypassed; search returned SQLite errors; sqlmap confirmed boolean- and time-based blind injection |
| SMB abuse | `smbclient //192.168.8.130/Users -U jimmy` after limited password guessing | Failed logons then a LogonType 3 success; files retrieved from the user profile |
| Reflected XSS | `<iframe src="javascript:alert('xss')">` in the `id` parameter of the order tracking page | Script executed in the browser |
| Network scanning | `nmap -sS` and `nmap -sV` against ports 1–1000 | Snort flagged both scans under the TCP portscan signature |
| Directory enumeration | gobuster against `common.txt` with `--exclude-length 80150` | `/ftp` discovered among roughly 16,000 logged requests |
| IDOR | Burp Suite replay of `/rest/basket/{id}` across sequential IDs | Other users' baskets returned HTTP 200 |
| Admin endpoint access | `curl` to `/rest/admin/application-configuration` without credentials | HTTP 200 with configuration and OAuth client details |
| Brute force | Burp Suite payload against `/rest/user/login` | 56 attempts from one source IP |
| Denial of service | `wrk -t500 -c500 -d180s` against the product search endpoint | Application became unreachable |
| Malware infection | EICAR string written as `Sales_Report_2026.pdf.exe` into the compromised user's Documents | Windows Defender quarantined the file on creation |
| Business logic abuse | Quantity set to `-1` on `POST /api/BasketItems` | Basket totalled -$4997.33 and checkout completed |
| CSRF | Hosted HTML form auto-submitting to `/profile` and `/profile/image/url` | Profile picture and username changed |

## Outcomes

- Four log sources normalised into one index: Juice Shop access logs, Windows Security, Windows Defender and Snort portscan events.
- Correlation across layers, with SMB authentication establishing the credential compromise that the malware detection later refers to, and scanning, enumeration and admin probing forming a single reconnaissance chain.
- Twelve alerts configured with severity ratings and routed to Triggered Alerts, on a one-minute cadence, real time for scanning and enumeration.
- Two detection gaps closed by instrumentation rather than query tuning: soft-404 handling for enumeration, and `basket_qty` logging for business logic abuse.
- Thresholds set against observed behaviour — 10 login attempts per source, 3 distinct basket IDs, 100 requests for volume alerting — rather than left at defaults.

## Key takeaways

- Application logs alone are insufficient at the web tier: soft-404 behaviour defeats status-code detection, and transaction parameters were absent until `server.js` was modified.
- Behaviour-based thresholds such as unique object IDs and request volume per source generalise better than payload signatures where a tool varies its requests.
- Endpoint, host and network telemetry answer different questions; Snort caught a SYN scan that produced no usable Windows events because no session completed.
- Severity needs justification from business impact rather than technical severity alone, which is why reflected XSS was rated Medium despite being a confirmed vulnerability.
- Alert tuning is continuous; the report recommends threshold refinement and the addition of firewall, endpoint detection and database log sources.

## Notes

- Academic exercise in a fully isolated virtual lab; all hosts, addresses and attack traffic are simulated and authorised.
- The report records the Juice Shop host under several capitalisations of the same name (`owaspjuicebox`, `OWASPJUICESHOP`); queries above use the form each detection was written with.
- The EICAR antivirus test string was used in place of real malware; no live malicious code was executed.
- Splunk Enterprise build number is not recorded in the report.
