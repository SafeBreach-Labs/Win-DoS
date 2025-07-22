# Win-DoS

A comprehensive framework implementing the "Win-DoS Epidemic" research, which discovered 5 critical vulnerabilities affecting Windows systems through novel attack techniques.

Created by SafeBreach Labs (Joint work of Or Yair and Shahak Morag).
For the full technical analysis check out the blog post - .

## Overview

This framework implements research that discovered 5 critical vulnerabilities affecting Windows systems:

### Win-DoS Vulnerabilities (4)
- **LDAP Referral DoS** (CVE-2025-32724) - Memory exhaustion via massive LDAP referral lists affecting Domain Controllers
- **NetLogon RPC DoS #1** (CVE-2025-26673) - Memory exhaustion in `NetrServerReqChallenge` function affecting Domain Controllers
- **NetLogon RPC DoS #2** (CVE-2025-49716) - Memory exhaustion in `DsrAddressToSiteNamesW` function affecting Domain Controllers
- **Spoolsv RPC DoS** (CVE-2025-49722) - Memory exhaustion in `RpcEnumPrinters` function affecting all Windows endpoints

### Win-DDoS Vulnerability (1)
- **LDAP Referral DDoS** (CVE-2025-32724) - Leveraging Domain Controllers as DDoS botnet participants without authentication

## Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd Win-DoS
   ```

2. **Install dependencies for specific modules:**
   - For LDAP attacks: `cd ldap_attacks && pip install -r requirements.txt`
   - For RPC attacks: `cd rpc_attacks && pip install -r requirements.txt`

## Module Documentation

### [LDAP Attacks](ldap_attacks/README.md)
Implements the LDAP referral attacks we discovered. Features:
- **DoS Mode**: Memory exhaustion via massive LDAP referral lists (500,000+ URLs)
- **DDoS Mode**: Leveraging Domain Controllers as botnet participants

### [RPC Attacks](torpedos_rpc_attacks/README.md)
Implements the RPC memory exhaustion attacks we discovered. Features:
- **TorpeDoS technique**: Pre-bind thousands of clients without waiting for bind acks, pre-sign packets if needed, and flood victims with many RPC calls at once

## Authors - Or Yair & Shahak Morag

|          | Or Yair                                         | Shahak Morag                                                  |
|----------|-------------------------------------------------|---------------------------------------------------------------|
| LinkedIn | [Or Yair](https://www.linkedin.com/in/or-yair/) | [Shahak Morag](https://www.linkedin.com/in/shahak-morag-6bb51b142/) |
| Twitter  | [@oryair1999](https://twitter.com/oryair1999)   | [@shahakmo](https://x.com/shahakmo)             |


