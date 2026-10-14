# 3x-ui Inbound Manager  v1.19.0

Terminal manager for the 3x-ui panel (v3.9.0 and later), connected with an admin API token.

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

    1  Check and install prerequisites        check Python, openssl, curl, acme.sh; apt install after CONFIRM
    2  Panel connection                        check, edit address and token
    3  Network and connection settings         Cloudflare IPs, domains, ports, local address, paths, fingerprint, AmneziaWG, relay
    4  Generate DIRECT Inbounds                asks the address first: domain, resolved IP, or 127.0.0.1
    5  Generate CDN Inbounds                   asks which Cloudflare IP to use, then lists CDN templates ("a" creates all)
    6  Generate FAKE SITE Inbounds             one address set as a fallback on a VLESS/Trojan TLS or REALITY master
    7  Generate RELAY Inbounds                 direct templates; the relay address replaces the connection address
    8  SSL certificate management              check or issue per domain, stored status
    9  Manage panel inbounds                   list, details, add, update, enable, delete, compare with local records
    10 Create inbound from template            all template types
    11 Export inbound inventory                JSON and YAML files with names, ports, addresses and paths
    12 Reports and statistics                  counts from the panel and local records, protocol support
    13 Backup and restore                      archive of templates, settings and local records
    0  Exit

## Address choices (menus 4 and 5)

The address question comes first. After you answer, the screen is cleared and the list of configs is shown,
then the next question (template number or "a") is asked.

- DIRECT (menu 4), asked once before any template is chosen:
  1) the direct domain name, 2) the IPv4 resolved from the direct domain (you confirm, or type another address),
  3) 127.0.0.1. The chosen address is stored in the local record (address field).
- CDN (menu 5): first the route is chosen, from three options.
  1) Through Cloudflare, domain name: the CDN domain (menu 3, item 5) is the address.
  2) Through Cloudflare, IP address: one of the Cloudflare IPs from menu 3, item 2 is the address. The port is taken
     from Cloudflare's proxied ports, never 80 or 443: TLS inbounds use the HTTPS list (2053, 2083, 2087, 2096, 8443),
     plain inbounds use the HTTP list (8080, 8880, 2052, 2082, 2086, 2095). Each inbound gets a different port.
     The list has only five usable HTTPS ports. 8443 is used first. When no Cloudflare port is left, the inbound is
     created on a random non-Cloudflare port and a warning says to change it to a Cloudflare port later.
  3) Local (HAProxy or Nginx): the address is the local IP from menu 3, item 7. Ports are not restricted.
  Routes 1 and 2 use Cloudflare's port list, never 80 or 443.
  The SNI and host header are always the CDN domain. The direct domain is never used as a CDN address.

## Host entries (panel v3.10.0)

The panel stores hosts as host groups. A host entry is sent to POST /panel/api/hosts/add as a group
(inboundIds, hosts, port, remark, security, sni, alpn, sortOrder). It is verified by reading
/panel/api/hosts/byInbound/{id}. Earlier versions of this tool sent a single host object, which the
panel refused with "request body failed validation".

## Request paths (menu 3, item 8)

"Generate all paths automatically?" defaults to yes. The generated list is shown, and you confirm before it is saved.
Answer n to set each path one by one (accept, type your own, or keep the current value).

## Request paths

Each path key is "<mode>_<transport>", for example direct_ws and cdn_ws, which are different values.
Keys: direct_ws, direct_xhttp, direct_grpc, direct_httpupgrade, direct_tcp, the same five for cdn, and
vmess, vless, trojan. Settings saved before this version used the old keys and must be regenerated in menu 3, item 8.

## Enabled inbounds and IP host headers

Every created inbound starts enabled (enable: true), so none needs manual enabling in the panel.
For DIRECT inbounds created over an IP address (option 2, or a typed IP), the transport Host header
(XHTTP host, WebSocket Host, HTTPUpgrade host, gRPC authority) is set to that IP. The TLS server name
and the certificate stay the domain. For option 3 (127.0.0.1) the Host headers keep the domain.
CDN inbounds keep the CDN domain as Host, because Cloudflare routes by it.

## REALITY: four modes, a client, and the server name

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

## Host entries and addresses

The address clients use is the host entry of an inbound (the panel builds subscriptions and outbounds from it).
- Every direct inbound gets a host entry whose address is the chosen direct address: the domain, the resolved IP,
  or 127.0.0.1. Over an IP, the TLS or REALITY server name (sni) is the domain. This gives the client outbound
  settings.address = IP and tlsSettings.serverName = domain, the same shape as a working Hysteria outbound.
- Templates with their own external proxy entries (for example some CDN and WS templates) keep those entries.
- Menu 9, item 8 (Repair addresses) checks existing managed inbounds against their saved address. It fixes host
  entry addresses, adds a missing host entry for direct inbounds, and sets the Host header of direct IP inbounds.
  It shows the plan first and changes nothing until you confirm.

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

`inbounds/` holds 21 default templates generated from
https://github.com/URT19/3x-ui-generator (commit 46439c4, file templates.js).
Regenerate with `python3 tools/build_templates.py` after updating `tools/source_templates.json`.

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
- Local CDN (HAProxy or Nginx): ports do not follow the Cloudflare rules (the earlier spec rule against Cloudflare
  ports for local mode is replaced by this).
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

## Inventory export (menu 11)

Reads the inbounds on the panel and merges them with local records. Each entry has: id, name, port, protocol,
connection mode, transport, security, address, domain, path, template and version, certificate file paths,
fingerprint, creation time, whether this tool created it (managed), and whether it is enabled on the panel.
Panel inbounds without a local record are listed as managed = false, with the fields the panel knows.
The export contains no API token and no private key content. It is written to `exports/` as
inbounds-<time>.json and inbounds-<time>.yaml, and the paths are shown at the end.
- Fake site and Relay have no templates in the library yet. Add JSON files with that connection_mode
  to inbounds/ and the menu lists them. No protocol settings were invented for them.

## Prerequisites (menu 1)

Checks Python 3.10 or newer, openssl (required), curl and acme.sh (optional). If openssl or curl is
missing and the system is Ubuntu, the apt-get command is shown as an argument list and runs only after
CONFIRM (with sudo when not root). acme.sh is never installed automatically, because its installer is a
remote script. Install it yourself, then check again.

## Backup and restore (menu 13)

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
