from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Coroutine, List, Optional, Tuple

from .exceptions import (AirlinkConnectionClosedError,
                         AirlinkSMSMessageDecodeError,
                         AirlinkSMSMessageEncodeError)

# Configure logging
logger = logging.getLogger(__name__)


class AirlinkSMSMessage:
    """
    Class which implements serialization as well as deserialization
    of SMS messages processed on Sierra Airlink devices.
    """

    AIRLINK_MESSAGE_START = "<<<"
    AIRLINK_MESSAGE_END = ">>>"
    AIRLINK_MESSAGE_MAX_LENGTH = 140  # Per the manual for the ES450
    DATA_TYPE_ASCII = "ASCII"

    def __init__(self, phone_number: str, message: str):
        if not phone_number.isnumeric():
            raise AirlinkSMSMessageDecodeError(
                "Cannot create an airlink message object with a non-numeric phone number!"
            )
        self.phone_number = phone_number
        self.message = message

    @property
    def length(self) -> int:
        """Returns the length of the message"""
        return len(self.message)

    def elaborate(self) -> List[AirlinkSMSMessage]:
        """
        Elaborates messages that are over the length limitation into a list of several messages that each are under the limit.
        """
        parts = [
            self.message[i : i + self.AIRLINK_MESSAGE_MAX_LENGTH]
            for i in range(0, self.length, self.AIRLINK_MESSAGE_MAX_LENGTH)
        ]
        return [AirlinkSMSMessage(phone_number=self.phone_number, message=part) for part in parts]

    def serialize(self) -> bytes:
        """
        Serializes the content of this object into a byte string that may
        be sent to an Airlink device for sending over a cellular network.
        """

        message_length = self.length
        if message_length > self.AIRLINK_MESSAGE_MAX_LENGTH:
            raise AirlinkSMSMessageEncodeError(
                f"Message of length {message_length} is too long to be sent as an SMS message!"
            )

        # Represent the message as a string of UPPERCASE hex characters
        encoded_message = self.message.encode("ascii").hex().upper()

        # Form the message
        serialized_message = (
            self.AIRLINK_MESSAGE_START
            + ",".join([self.phone_number, self.DATA_TYPE_ASCII, str(message_length), encoded_message])
            + self.AIRLINK_MESSAGE_END
        )
        return serialized_message.encode("ascii")

    @classmethod
    def deserialize(cls, message_bytes: bytes) -> AirlinkSMSMessage:
        """
        Deserializes a message from the UDP schema to an AirlinkSMSMessage object
        """
        try:
            message = message_bytes.decode()
        except UnicodeDecodeError as exc:
            raise AirlinkSMSMessageDecodeError("Failed to decode airlink message as as unicode text!") from exc

        if not (message.startswith(cls.AIRLINK_MESSAGE_START) and message.endswith(cls.AIRLINK_MESSAGE_END)):
            raise AirlinkSMSMessageDecodeError("Received airlink message with invalid start and/or ending delimiters!")

        # Remove the delimiters <<< and >>>
        content = message[3:-3]

        # Split the content by commas
        parts = content.split(",")
        if len(parts) != 4:
            raise AirlinkSMSMessageDecodeError("Received airlink message with invalid number of fields!")

        sender_phone_number, data_type, length_str, hex_message = parts

        # Validate and process the fields
        if data_type != cls.DATA_TYPE_ASCII:
            raise AirlinkSMSMessageDecodeError(f"Unable to process message data type of {data_type}")

        try:
            length = int(length_str)
        except ValueError as exc:
            raise AirlinkSMSMessageDecodeError(f"Unable to parse message length of {length_str}") from exc

        # Decode the hex message to ASCII
        try:
            decoded_message = bytes.fromhex(hex_message).decode("ascii")
        except ValueError as exc:
            raise AirlinkSMSMessageDecodeError(f"Unable to parse hex encoded message of {hex_message}") from exc

        # Validate the length
        decoded_message_length = len(decoded_message)
        if decoded_message_length != length:
            raise AirlinkSMSMessageDecodeError(
                "Decoded message length mismatch: expected {length}, got {decoded_message_length}"
            )

        return cls(phone_number=sender_phone_number, message=decoded_message)

    def __repr__(self) -> str:
        return f"<class {self.__class__.__name__}: phone_number: '{self.phone_number}', message: '{self.message}'>"


class AirlinkSMSUDPClientProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport: Optional[asyncio.DatagramTransport] = None

    def error_received(self, exc):
        logger.error("Exception in UDP socket communication:", exc_info=exc)

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        logger.debug("Message send returned: %s", data.decode())

    def connection_lost(self, exc: Optional[Exception]):
        if exc is not None:
            logger.exception("Airlink UDP client socket closed due to error:", exc_info=exc)
        self.transport = None

    def send(self, message: AirlinkSMSMessage):
        """
        Sends a message, elaborating out the message into several
        in case the message length is too long.

        Raises AirlinkConnectionClosedError if the socket is closed or AirlinkSMSMessageEncodeError if the message is unable to be formatted.
        """
        if self.transport is None:
            raise AirlinkConnectionClosedError("Unable to send messages when the client socket has been closed")
        try:
            for msg in message.elaborate():
                logger.debug("Sending reply message: %s", msg)
                serialized_message = msg.serialize()
                self.transport.sendto(serialized_message)
        except AirlinkSMSMessageEncodeError as exc:
            raise exc


class AirlinkSMSUDPServerProtocol(AirlinkSMSUDPClientProtocol):
    def __init__(
        self,
        reply_client: AirlinkSMSUDPClientProtocol,
        on_message_received: Optional[
            Callable[[AirlinkSMSMessage, AirlinkSMSUDPClientProtocol], Coroutine[None, None, bool]]
        ] = None,
        on_connection_lost: Optional[asyncio.Future[bool]] = None,
    ):
        super().__init__()
        self.reply_client = reply_client
        self.on_message_received = on_message_received
        self.on_connection_lost = on_connection_lost
        self._pending_replies = set()

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
        sockname = transport.get_extra_info("sockname")
        logger.debug("Airlink SMS UDP server is up and listening on %s...", sockname)

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        logger.debug("Received packet from %s with payload of %s", addr, data)
        message = AirlinkSMSMessage.deserialize(data)
        if self.on_message_received is not None:
            logger.debug("Calling on_message_received handler with %s", message)
            reply_task = asyncio.create_task(self.on_message_received(message, self.reply_client))
            self._pending_replies.add(reply_task)
            reply_task.add_done_callback(self._pending_replies.discard)

    def connection_lost(self, exc: Optional[Exception]):
        logger.info("Connection closed")
        if self.on_connection_lost is not None:
            self.on_connection_lost.set_result(True)
        super().connection_lost(exc)


async def create_message_handler(
    remote_addr: str,
    remote_port: int,
    local_bind_addr: str,
    local_bind_port: int,
    on_message_received: Callable[[AirlinkSMSMessage, AirlinkSMSUDPClientProtocol], Coroutine[None, None, bool]],
) -> asyncio.Future[bool]:
    """
    Create a UDP server as well as client to communicate with an Airlink device,
    which is capable of receiving messages as well as sending replies.

    Returns a future which returns if the server exits.
    """
    logger.debug(
        "Creating Airlink message handler, remote_addr=%s, remote_port=%s, local_bind_addr=%s, local_bind_port=%s",
        remote_addr,
        remote_port,
        local_bind_addr,
        local_bind_port,
    )
    loop = asyncio.get_running_loop()
    server_done: asyncio.Future[bool] = asyncio.Future(loop=loop)

    # Create a UDP client for egress messages
    client_transport, client_protocol = await loop.create_datagram_endpoint(
        lambda: AirlinkSMSUDPClientProtocol(), remote_addr=(remote_addr, remote_port)
    )

    # Create the server, providing a handle to the client protocol
    # such that we are able to send replies.
    server_transport, server_protocol = await loop.create_datagram_endpoint(
        lambda: AirlinkSMSUDPServerProtocol(
            reply_client=client_protocol, on_message_received=on_message_received, on_connection_lost=server_done
        ),
        local_addr=(local_bind_addr, local_bind_port),
    )
    return server_done
