# Free No-Key Endpoint API Research

This document records endpoint families that can support PureLink's IP/domain abuse, purity, DNS, and health checks without requiring an API key. Usage terms and rate limits can change; verify each provider before production use.

## Recommended Endpoint Families

| # | Service | Example endpoint | Checks | Response | Caveats / limits | PureLink integration value | Source |
|---|---------|------------------|--------|----------|------------------|----------------------------|--------|
| 1 | ipapi.is | `GET https://api.ipapi.is?q=<IP>` | Datacenter, Tor, proxy, VPN, abuser, ASN, company, geolocation | JSON | Free no-key tier observed as 1,000 requests/day; higher volume may require a key. | Primary combined abuse/purity signal. | <https://ipapi.is/developers.html> |
| 2 | IPLogs | `POST https://iplogs.com/v1/check` with `{"ip":"x.x.x.x"}` | VPN/proxy/Tor/datacenter verdict, score, and multi-layer signals | JSON | Public docs indicated about 60 requests/minute per source IP; provider behavior may change. | High-fidelity proxy/VPN scoring for purity checks. | <https://iplogs.com/> and <https://github.com/DigitalDTech/iplogs-api> |
| 3 | GetIPIntel | `GET http://check.getipintel.net/check.php?ip=<IP>&contact=<email>` | Proxy, VPN, hosting, bad-IP probability score | Plain text or JSON | Requires valid contact email, attribution, and TOS compliance; no random/incremental scanning. | Probability-based secondary risk score. | <https://getipintel.net/> |
| 4 | IPPure | `GET https://my.ippure.com/v1/info` | Caller-IP risk score, residential/datacenter, ASN, location | JSON | Beta; arbitrary target-IP lookup was not confirmed in prior research. | Potential self-IP purity/risk signal only until target lookup is verified. | <https://ippure.com/en/MyIP-Info-API> |
| 5 | Blackbox / ipinfo.app | `GET https://blackbox.ipinfo.app/api/v1/<IP>` | Proxy/hosting/Tor yes/no; beta API classifies VPN/hosting/Tor/residential/mobile | Plain text or JSON beta | v1 described as free/unlimited; v3 beta may later require payment or a key. | Fast boolean filter before richer provider calls. | <https://blackbox.ipinfo.app/> |
| 6 | ip-api.com | `GET http://ip-api.com/json/<IP>?fields=proxy,hosting,mobile,country,isp,as,query` | Geolocation, ISP, ASN, proxy, hosting, mobile | JSON | Free endpoint is non-commercial and HTTP-only. | Quick triage for geo, ASN, and hosting/proxy flags. | <https://ip-api.com/docs/api:json> |
| 7 | iplookup.it | `GET https://www.iplookup.it/ip/<IP>` and `POST https://www.iplookup.it/ip/batch` | Geo, ASN, reverse DNS, VPN/proxy/Tor/hosting flags | JSON | Free tier supports no-key use; handle 429 responses with backoff. | Batch-friendly enrichment for host lists. | <https://www.iplookup.it/docs> |
| 8 | RustyIP / ip.nc.gy | `GET https://ip.nc.gy/json?ip=<IP>` or flag paths such as `/proxy` and `/vpn` | Geo, ASN, proxy, VPN, Tor, hosting, CDN, school, anonymous flags | JSON or plain text | No key; open-source backend and data quality depend on upstream datasets. | Modular low-overhead signal checks. | <https://github.com/NetworkCats/rustyip> |
| 9 | IPPriv | `GET https://api.ippriv.com/api/security/<IP>` | VPN, proxy, Tor, hosting, ASN, organization | JSON | Free no-auth endpoint per public docs; monitor for quota changes. | Focused security-only enrichment. | <https://www.ippriv.com/api-docs> |
| 10 | IPDetails.io | Public site advertises free API access | Geo, ASN, hosting, VPN, Tor, proxy, abuse signals | JSON | Exact endpoint pattern was not fully confirmed in prior research; verify before integration. | Candidate provider after live endpoint confirmation. | <https://ipdetails.io/> |
| 11 | Google Public DNS DoH JSON | `GET https://dns.google/resolve?name=<domain>&type=A` | DNS A/AAAA/MX/TXT/CNAME resolution and DNSSEC metadata | JSON | Not an abuse feed; Google receives queried names. | Domain-to-IP validation and DNS health checks. | <https://developers.google.com/speed/public-dns/docs/doh/json> |
| 12 | Cloudflare DNS DoH JSON | `GET https://cloudflare-dns.com/dns-query?name=<domain>&type=A` with `Accept: application/dns-json` | DNS resolution using Cloudflare's DoH service | JSON | Not an abuse feed; Cloudflare receives queried names. | Cross-check DNS results against Google. | <https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/> |
| 13 | BigDataCloud Free APIs | Client-oriented free API endpoints | Client IP detection, client info, roaming/network hints | JSON | Mostly browser/client-IP oriented; not a server-side abuse API. | Lightweight self-IP detection or client context support. | <https://www.bigdatacloud.com/free-api> |

## Integration Guidance

- Prefer at least two independent providers for any final abuse or purity verdict.
- Treat DNS endpoints as supporting evidence only; they do not provide reputation scoring.
- Respect provider-specific terms, especially GetIPIntel attribution/contact requirements and ip-api.com's non-commercial free tier.
- Add per-provider timeouts, retry budgets, and 429 backoff before enabling batch mode.
- Preserve privacy by documenting which third-party providers receive IPs, domains, or contact email parameters.

## Reliability Labels

- Confirmed no-key in prior research: ipapi.is, IPLogs, GetIPIntel, ip-api.com, iplookup.it, RustyIP/ip.nc.gy, Blackbox, IPPriv, Google Public DNS, and Cloudflare DNS.
- Stability concerns: IPPure beta behavior, Blackbox v3 beta behavior, and IPDetails.io endpoint-path uncertainty.
- Commercial-use caution: ip-api.com free endpoint is explicitly non-commercial; GetIPIntel imposes strict acceptable-use requirements.
