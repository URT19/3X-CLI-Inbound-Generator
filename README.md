# 3X CLI Inbound Generator  v1.33.1


[توضیحات فارسی](https://github.com/URT19/3X-CLI-Inbound-Generator/blob/main/readme-fa.md)


Interactive terminal manager for the Sanaei 3x-ui panel (v3.9.0 and later, checked against v3.10.0). It creates
DIRECT, CDN (behind Cloudflare), relay, fake-site and fallback inbounds from JSON templates, checks and requests
SSL certificates, and exports an inventory. Every change to the panel is previewed and confirmed first.

Repository: https://github.com/URT19/3X-CLI-Inbound-Generator/

## Requirements

- Ubuntu (other Linux systems work for everything except the package installer in menu 1)
- Python 3.10 or newer, standard library only (no `pip install`)
- `openssl` (certificate checks and key generation)
- Optional: `curl`, `acme.sh` (certificate issuing)
- A 3x-ui admin API token

    sudo apt install -y python3 openssl curl unzip

## Install

Download the release and run it:

    wget https://github.com/URT19/3X-CLI-Inbound-Generator/releases/download/v1.33.0/3X-CLI-Inbound-Generator-1.33.0.zip
    unzip 3X-CLI-Inbound-Generator-1.33.0.zip
    cd <the extracted folder>
    python3 main.py

Or clone the repository:

    git clone https://github.com/URT19/3X-CLI-Inbound-Generator.git
    cd 3X-CLI-Inbound-Generator
    python3 main.py

## Update

Download the new release into a new folder and copy your `config/settings.json` (and `state/` if you want to keep
the local records) into it. Do not unzip a new release over an old folder: unzip never removes files, so templates
that were deleted or renamed in the new release stay behind in `inbounds/` and show up in the menus. If you did
unzip over an old folder, delete `inbounds/` and unzip again.

## Tests

    python3 -m unittest discover -s tests -t .      # 330 tests, no panel needed
    pip install pyyaml                              # optional, only enables the YAML export tests

## Important notes

- Not affiliated with 3x-ui. Use at your own risk: test on a panel you can restore first (menu 10 makes a backup).
- Your API token is stored in plain text in `config/settings.json` (mode 0600). That file, `state/local_inbounds/`,
  `exports/` and `backups/` are listed in `.gitignore`. Never commit or share them.
- The Cloudflare port list in `config/cloudflare_ports.json` can go out of date. Check it against Cloudflare's docs.

## Credits

Panel: https://github.com/MHSanaei/3x-ui. The default inbound templates were extracted from the author's earlier
project https://github.com/URT19/3x-ui-generator (commit 46439c4, file `templates.js`).

## Run

    python3 main.py

The first start has no settings. Open menu 2, then "Edit address and token".

## Settings

Stored in `config/settings.json` (created by menu 2, mode 0600). It holds the panel address,
the API token, TLS verification and the certificate root (`/cert_folder/cert` by default).
The token is stored in plain text, so protect the file and the machine. The screen only
shows the last four characters of the token. Do not copy this file into shared places.

## Network settings (menu 3)

Stored under `network` in settings.json. Domains and IPs are validated. Ports 80 and 443 are
always refused. A local address must be loopback or private, and a local port must not be a
Cloudflare HTTP or HTTPS port. The Cloudflare list is in `config/cloudflare_ports.json`
(source: developers.cloudflare.com network-ports page, retrieved 2026-10-13). Update that file
when Cloudflare changes its list. Ports already used by panel inbounds are checked when an
inbound is created, not when the setting is saved.

## SSL (menu 8)

Certificates live in `<cert_root>/<domain>/fullchain.pem` and `<cert_root>/<domain>/privkey.pem`
(cert_root defaults to /cert_folder/cert). The flow asks whether the domain needs SSL, and if
a certificate is already issued. An existing certificate is checked for:

- file presence and parsing,
- names that cover the domain (wildcards cover one label),
- a private key that matches the certificate,
- expiry, with renewal suggested at 30 days or less.

File presence alone is not treated as valid. Key material is never printed.

Issuing uses acme.sh the same way the panel's installer does: Let's Encrypt, standalone
HTTP-01 on the chosen port (default 80), then --installcert into the spec layout.
Requirements and limits:

- acme.sh must already exist at ~/.acme.sh/acme.sh. Installing it is not automated yet,
  because it runs a remote script.
- The HTTP-01 port must be reachable from the internet during validation.
- The commands are built as argument lists, shown in a preview, and need CONFIRM.
- No service is restarted. The panel installer restarts x-ui through its reload command.
  This tool does not, so the operator decides when to restart.
- The panel's own API has no certificate route. The ACME work is done with acme.sh directly.

## Menu

    1  Check and install prerequisites
    2  Panel connection
    3  Network and connection settings
    4  Generate Inbounds
         1) DIRECT
         2) CDN
         3) FAKE SITE
         4) RELAY
         5) Generate Fallback Proxies (plain WS, TCP, HTTPUpgrade on 127.0.0.1, FB in the name)
         0) Back
    5  SSL certificate management
    6  Manage panel inbounds (list, details, add, update, enable, delete, compare, repair paths, listen 127.0.0.1)
    7  Create inbound from template
    8  Export inbound inventory (JSON and YAML)
    9  Reports and statistics
    10 Backup and restore
    0  Exit

## Address choices (menus 4 and 5)

The address question comes first. After you answer, the screen is cleared and the list of configs is shown,
then the next question (template number or "a") is asked.

- DIRECT (menu 4), asked once before any template is chosen:
  1) the direct domain name, 2) the IPv4 resolved from the direct domain (you confirm, or type another address),
  3) 127.0.0.1. The chosen address is stored in the local record (address field).
- CDN (menu 5): TLS only. There are no plain (non-TLS) CDN templates. Questions, in order:
  1) Domain or IP? Domain: the CDN domain already registered (menu 3, item 5) is shown and you choose to use it or
     type another one (the new one is saved as the CDN domain). The SSL certificate is then checked; if it is
     missing, invalid or due for renewal, you are asked whether to obtain it. IP: one of the Cloudflare IPs from
     menu 3, item 2.
  2) Add the ECH config list `cloudflare-ech.com+udp://1.1.1.1` (tlsSettings.settings.echConfigList)? Default yes.
  3) Set finalmask (TCP fragment, two fragment entries, see network/cdn.py)? Default no. Applied as
     streamSettings.finalmask.
  4) Template number, or a for all (default a).
  ALPN is `http/1.1`, except VLESS gRPC and both xHTTP templates (`h2` only; hand tests showed xHTTP never
  worked behind Cloudflare with `http/1.1` alone, and noSSEHeader broke it). All 13 Cipher Suites are set. Reject Unknown SNI is off on
  HTTPUpgrade, gRPC and VMess WS. The packet-up xHTTP keeps up to 100 buffered POSTs. The transport Host header and SNI are the CDN domain.
  Only six CDN templates exist, each with a fixed port (menu 3 port settings are not used for them):
  VLESS WS TLS 8443, VLESS HTTPUpgrade TLS 2053, VLESS xHTTP TLS (packet-up) 2083, VLESS gRPC TLS 2087,
  VMess WS TLS 2096, and VLESS xHTTP stream-up TLS 44300. Port 44300 is an origin port, not a Cloudflare port:
  add a Cloudflare origin rule that sends a Cloudflare port to it, and use that Cloudflare port in the host.
  A port already used on the panel is refused, not replaced. The templates are generated by
  `tools/build_cdn_templates.py` from the matching TLS direct templates.
  After the inbounds are created, ONE host named CDN is created with the chosen domain or IP and attached to
  every CDN inbound of that run.

- CDN test (menu 4, item 6): XHTTP matrix. Builds 15 variants of the CDN xHTTP template on random ports (TLS ports
  end with 3, never Cloudflare ports, menu 3 fixed port ignored): mode (auto, packet-up, stream-up, stream-one) x ALPN
  (http/1.1, h2, h2 + http/1.1), packet-up with noSSEHeader on h1 and h2, and a minimal variant (path, host, mode only).
  Names look like `51-VLESS-XHTTP-XT-PU-H1-TLS` (XT = test, PU = packet-up, H1 = http/1.1; AU auto, SU stream-up,
  SO stream-one, H2 h2, H12 both, NS noSSEHeader, MIN minimal). It asks the same address, ECH and finalmask questions,
  creates one CDN host, and prints name and port of every inbound. Set each port on Cloudflare by hand to test.

## Request paths (menu 3, item 8)

"Generate all paths automatically?" defaults to yes. The generated list is shown, and you confirm before it is saved.
Answer n to set each path one by one (accept, type your own, or keep the current value).

## Request paths

Each path key is "<mode>_<transport>", for example direct_ws and cdn_ws, which are different values.
Keys: direct_ws, direct_xhttp, direct_grpc, direct_httpupgrade, direct_tcp, the same five for cdn, and
vmess, vless, trojan. Settings saved before this version used the old keys and must be regenerated in menu 3, item 8.

## Enabled inbounds and IP Host headers (inbound settings)

Every created inbound starts enabled (enable: true), so none needs manual enabling in the panel.
For DIRECT inbounds created over an IP address (option 2, or a typed IP), the transport Host header
(XHTTP host, WebSocket Host, HTTPUpgrade host, gRPC authority) is set to that IP. The TLS server name
and the certificate stay the domain. For option 3 (127.0.0.1) the Host headers keep the domain.
CDN inbounds keep the CDN domain as Host, because Cloudflare routes by it.

## REALITY: four modes and the server name

Four REALITY templates, following the reference outbound (VLESS, REALITY, serverName = the REALITY target SNI,
publicKey, shortId, fingerprint, flow on the client):
- 25 VLESS Reality Vision (TCP): client flow xtls-rprx-vision (the v2ray-agent mode).
- 26 VLESS gRPC REALITY: no flow.
- 27 VLESS XHTTP REALITY: no flow.
- 30 VLESS Reality TCP (no Vision flow): no flow.

Clients are not created by this tool: direct inbounds are created without clients, as requested.
The REALITY public key is stored in the inbound (streamSettings.realitySettings.settings.publicKey), as the panel
expects. The host entry's sni is the server name for TLS (the direct domain) and REALITY (the REALITY target SNI).
Hysteria's tlsSettings.serverName is the direct domain.

## Start-up session check

When a panel is configured, the connection is checked once at start-up and the result is shown in the
header ("connected, N inbounds" or "last check failed"). Keys typed in a non-UTF-8 layout no longer crash the
menu: invalid bytes are read as an invalid option and the question is asked again.

## Xray deprecation warnings

Xray-core warns about these features: VMess, Trojan without flow, and the WebSocket, gRPC and HTTPUpgrade
transports. Templates that use them are marked [deprecated] in every listing and show a warning when chosen.
"a" (create all) includes them, as requested; the batch shows how many are deprecated before the confirmation. Replacements already in
the library: XHTTP templates (VLESS and VMess XHTTP, CDN and direct), VLESS TCP TLS Vision (28) for Trojan, and
the REALITY templates (25, 26, 27). Note: the VMess to VLESS-encryption migration needs the panel's key
generator (GET /panel/api/server/getNewVlessEnc) and is not implemented yet.

## Listen on 127.0.0.1 for all inbounds (menu 6, item 9)

Sets listen = 127.0.0.1 on every inbound on the panel, for a setup where nginx (later nginx or haproxy)
receives the public connections. Before anything changes:
- a red warning says that without a matching nginx setup, all connections are cut;
- you are offered a panel database backup through the API (GET /panel/api/server/getDb), saved in backups/
  with mode 600. It contains secrets: keep it private;
- you must type CONFIRM in capital letters (anything else cancels).
Host entries are not changed. Xray must be restarted afterwards. Item 10 restores managed inbounds to all addresses.

## Direct domain 2 and VMess

- Menu 3, item 14 sets a second direct domain. VLESS TCP TLS Vision (template 28) uses it as address, SNI and
  certificate, so it does not share a domain with other TLS-over-TCP inbounds.
- VMess over TCP with TLS (template 02) is deprecated and shares a domain with VLESS. It is created only after
  an explicit yes (default no). In a batch, one question decides for all such templates.

## Confirmations

Every change asks "Apply? [Y/n]". Enter means yes. Type n to cancel. Restore and delete use the same prompt.

## Batch creation

Menus 4 to 8 list their templates. Enter a number to create one, or "a" to create all of them. The batch
resolves every template first and shows the names and ports. Templates with missing values are skipped and listed.
One confirmation covers all inbounds and their host entries.

## SSL after a domain is set

Menu 3 items 4 and 5 check the certificate for the domain right after it is saved. If it is missing, invalid or
expired, the menu asks whether to obtain one now. If it is due for renewal, it asks whether to renew.

## Creating inbounds (menus 4, 5, 10)

Nothing is asked during creation except the template choice and the confirmation.
The values come from the saved settings:

- Port: the fixed port, or a random port from the range, checked against the panel.
- Domains: direct domain (menu 3, item 4) and CDN domain (item 5).
- Cloudflare address: the first Cloudflare IP (used by the external proxy host entries).
- Paths: menu 3, item 8. Each path is 12 random characters unless you type your own.
- Certificates: <cert_root>/<domain>/fullchain.pem and privkey.pem. They must be readable
  and pass the SSL check (valid, or due for renewal).
- TLS fingerprint: menu 3, item 9 (default chrome).
- Name: generated from the template number, protocol, transport and mode.

All checks run before anything is sent. The panel is called only after the preview and CONFIRM.
After a verified creation, the values used are saved in `state/local_inbounds/direct.json` or
`cdn.json`. Earlier records are not changed when settings change.

## Inbound library

`inbounds/` holds 31 default templates, mostly extracted from
https://github.com/URT19/3x-ui-generator (commit 46439c4, file templates.js). The CDN set is generated from the TLS
direct templates by `tools/build_cdn_templates.py`. Templates are plain JSON: edit or add files in `inbounds/`.
`tools/build_templates.py` regenerates the non-CDN templates from `tools/source_templates.json` (the extracted
`templates.js`, made with `tools/extract_templates.js`).

Templates have no fixed port. The port is entered when the inbound is created.
Ports 80 and 443 are refused. The source template 12 default (443) is not used.
Placeholders such as {{SUBDOMAIN_DIRECT}} and {{CERT_CDN}} are asked for at creation time.

Legacy `streamSettings.externalProxy` entries from the source are created as host entries
through `/panel/api/hosts/add` after the inbound is verified (field mapping follows
`externalProxyEntryToHost` in the panel source).

Certificate checks: the panel only checks that certificate and key paths are non-empty when
an inbound is added. It does not check that the files exist.

## Names

Default names look like `12-VLESS-XHTTP-CDN-TLS`. They start with the template number, use ASCII,
and are at most 32 characters. If a name already exists, `-2`, `-3`, ... is added within the limit.
A custom name must start with a number, be ASCII, and be at most 32 characters.

The project spec asked for 16 characters. The limit is 32 by request.
The codename and icon parts of the spec are not implemented yet.

## Safety

- Nothing is sent to the panel without typing CONFIRM after a dry-run preview.
- Ports 80 and 443 are reserved. Name and port conflicts are refused before sending.
- Success is reported only after the panel state is read back and matches.
- Client management, bulkDel and import are not implemented yet.

## Known limits

- Nothing here has been run against a live 3x-ui instance. Tests use an in-memory fake panel.
- Panel inbounds do not store their template version, so lists show the panel data only.
- Relay (menu 8): uses the direct templates. Names contain RELAY (for example 02-VMESS-TCP-RELAY-TLS). The
  relay address (menu 3, item 11) gets a host entry for each relay inbound. Records go to relay.json.
- IP option (menu 3, item 10): on means connection addresses (record address, relay host address) use the
  IPv4 address behind the domain. TLS server names and certificates still use the domain.
- Fake site (menu 7): one address (port, or host:port) becomes a fallback rule (childId 0, name fake-site)
  on a VLESS or Trojan master that uses TCP with TLS or REALITY. Existing fallback rules are sent back unchanged.
  A previous fake-site rule is replaced. Ports 80 and 443 are refused. The panel needs an Xray restart after
  the change; the tool reports that but does not restart.
- Hysteria2 (protocol hysteria, UDP): template tls_hysteria_direct, built from the panel example. Only the
  salamander password is random (16 letters and digits, new for each inbound). The certificate comes from the
  direct domain (<cert_root>/<direct domain>/). The password is shown in the preview and is stored only on the
  panel, not in local records or exports.
- TUIC (tls_tuic_direct): native UDP server with certificate and key from the direct domain, SNI from the direct domain.
- AmneziaWG (udp_amneziawg_direct): keys and parameters from menu 3 item 12. The tool proposes values; you accept
  them or change each one. The values are saved in settings.json under "amnezia". Keys are made with openssl (X25519).
- AmneziaWG proposals follow the panel's limits (internal/amneziawg/params.go): S4 is 12 to 27 in proposals and
  must be 0 to 32 on save, S1+56 must not equal S2, H values are distinct and at least 5, and the rekey maximum
  must be below the reject minimum.
- Names that already exist on the panel get -2, -3 and so on. Remove old test inbounds before a real run.
- CDN configs always go through Cloudflare. There is no local route for them any more.
- Hysteria2 (tls_hysteria_direct): TLS needs a certificate. The panel (validateInboundTLSCertificates) refuses
  any TLS inbound without one, so the template uses the direct domain certificate (CERT_DIRECT, KEY_DIRECT),
  the same as the other direct TLS templates. ECH does not replace this check. The salamander password is random
  and saved in settings.json (hysteria_passwords) and in the local record.
- VLESS Reality Vision (tcp_reality_vision_direct, number 25): no certificate and no Nginx. When it is chosen, a
  target is asked: one of the default sites (Microsoft, Apple, Bing, Amazon, Yahoo) or a custom host:443 with an SNI.
  The default sites are suggestions. Check each from the server (TLS 1.3 and HTTP/2) before use. Each inbound gets a
  new X25519 pair (openssl, base64url) and a random 16-hex short ID. The private key is stored in settings.json
  (reality_keys), not in the local record or exports. The public key, short ID, target and SNI are in the record.
  The fingerprint comes from menu 3, item 9.
- REALITY variants (all direct, no certificate, same target and key handling as Vision):
  25 VLESS Reality Vision (TCP, flow xtls-rprx-vision on the client), 26 VLESS gRPC REALITY (path from
  direct_grpc), 27 VLESS XHTTP REALITY (path from direct_xhttp). A plain TCP REALITY without Vision needs no
  separate server template: the server side is the same as 25, and only the client flow differs.
- VLESS TCP TLS Vision (28) and Trojan TCP TLS (29), both direct, from v2ray-agent's Xray inbounds. The
  Nginx fallbacks of that project are removed: the server listens on the public port and needs the direct
  domain certificate. Vision's flow (xtls-rprx-vision) is set on each client when clients are added.
- REALITY ports: 8443 is used when it is free (random port mode); 443 is never used for inbounds.
- Protocol support is listed in config/protocols.json (checked against panel source v3.10.0).
  Templates exist for VMess, VLESS and Trojan only. amneziawg, masque, hysteria, tuic and mtproto are
  "pending". Fake site and relay have no templates yet.

## Inventory export (menu 8)

Reads the inbounds on the panel and merges them with local records. Each entry has: id, name, port, protocol,
connection mode, transport, security, address, domain, path, template and version, certificate file paths,
fingerprint, creation time, whether this tool created it (managed), and whether it is enabled on the panel.
Panel inbounds without a local record are listed as managed = false, with the fields the panel knows.
The export contains no API token and no private key content. It is written to `exports/` as
inbounds-<time>.json and inbounds-<time>.yaml, and the paths are shown at the end.
- Fake site and Relay have no templates in the library yet. Add JSON files with that connection_mode
  to inbounds/ and the menu lists them. No protocol settings were invented for them.

## Prerequisites (menu 1)

Checks Python 3.10 or newer and openssl (required). Optional: curl, haproxy and nginx (needed for menu 11,
proxy aggregation), and acme.sh. If openssl, curl, haproxy or nginx is
missing and the system is Ubuntu, the apt-get command is shown as an argument list and runs only after
CONFIRM (with sudo when not root). acme.sh is never installed automatically, because its installer is a
remote script. Install it yourself, then check again.

## Backup and restore (menu 10)

Backup (tar.gz, mode 0600) holds:
- inbounds/*.json: inbound templates
- config/settings.json: settings, including the API token
- config/cloudflare_ports.json
- state/local_inbounds/*.json: records of inbounds created here

Backups are written to `backups/`. manifest.json has the app version, time, and SHA-256 of every file.
Restore first checks every archive entry name (no absolute paths, no "..") and every hash, and loads the
templates and settings. Only then does it save the current files to a safety backup and write the restored
files. If writing fails, the previous files are put back. After a restore the settings and templates reload.
Keep backups private: they contain the API token.
- Direct with IP uses only the plain TCP template (http_tcp_direct_vmess). The other direct templates need a domain
  and a certificate, so they cannot be used with an IP address without a new template.
- Menu 10 item 7 compares local records with the panel. It is read-only: it reports differences and never changes
  local files or the panel.
- Random ports are chosen when an inbound is created. The menu 4 to 8 flows that use them are not built yet.

## Tests

    python3 -m unittest discover -s tests -t .

## What this version does not do

- It never adds clients or host entries to x-ui. Inbounds are created without clients, and subscription hosts are
  left to the panel.
- It does not configure, start, stop, or restart HAProxy or Nginx, and it does not write their configuration. Those
  steps are described separately.
- The HAProxy and Nginx generator, the aggregation wizard, the hub inbound, and the PROXY protocol option were removed.

## Fallback proxies (menu 4, item 5)

Five plain (no TLS) inbounds on 127.0.0.1, named NN-PROTOCOL-TRANSPORT-FB:
31-VLESS-WS-FB, 32-VLESS-TCP-FB, 33-VLESS-HTTPUP-FB, 34-TROJAN-WS-FB, 35-TROJAN-HTTPUP-FB.
Each has its own random path (WS and HTTPUpgrade), an empty host, and acceptProxyProtocol false. WS has
heartbeatPeriod 30. VLESS TCP has the testseed from the reference config. VMess and Trojan TCP are not in the list.
No address is asked, and no hosts or clients are created.

Names no longer end with PLAIN. The suffix is kept only for TLS (-TLS) and REALITY (-REALITY).

## Port rules (current)

- Plain (no TLS) inbounds: the port ends with 80, for example 3080 or 21080.
- TLS inbounds: the port ends with 3, for example 20003.
- REALITY inbounds: the port ends with 5, for example 20005.
- Ports 80 and 443 are never used. Cloudflare's HTTP and HTTPS ports are reserved for CDN configurations, so non-CDN
  inbounds never use them (this includes 8443 and 8080).
- A fixed port must match its ending and must not be reserved.

## Direct TLS templates

Besides VLESS TCP TLS Vision (direct domain 2), the direct TLS set now includes VMess WS, VLESS gRPC, and VLESS
HTTPUpgrade (templates 36, 37 and 38). The VMess WS template is marked deprecated by Xray, as are the other WS, gRPC
and HTTPUpgrade templates.

## Duplicate removed

Template 30 (VLESS Reality TCP without Vision) was removed. On the server it is the same REALITY inbound as 25, so
the two only differed in the client flow.

## IP host

When a run uses an IP address (direct option 2 or a typed IP, ), the tool
creates ONE host group named IP after the inbounds are created. It holds the confirmed address and is attached to
every inbound created in that run. Port is 0 and sni is empty, so each inbound keeps its own port and server name.
This is the only host entry the tool creates. Domain and 127.0.0.1 runs create no host.

## VMess WS TLS (template 36)

ALPN is h2 only. HTTP/1.1 is not listed.
