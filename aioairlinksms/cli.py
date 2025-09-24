import logging
from typing import Callable

import asyncclick as click

from aioairlinksms.udp import AirlinkSMSMessage, create_message_handler


@click.command()
@click.option("-h", "--remote-addr", required=True, help="Remote address of the device to send messages to.")
@click.option("-p", "--remote-port", required=True, type=int, help="Remote port on the device to send messages to")
@click.option("-H", "--local-bind-addr", default="0.0.0.0", help="Local address to bind the listening server to.")
@click.option("-P", "--local-bind-port", required=False, type=int, help="Local port to bind the listening server to.")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
async def main(remote_addr, remote_port, local_bind_addr, local_bind_port, verbose):
    """
    A CLI for receiving Airlink SMS messages and replying with the character count.
    """
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    def on_message_received(message: AirlinkSMSMessage, reply_client: Callable[[AirlinkSMSMessage], None]) -> bool:
        """
        Handles received messages, prints them, and replies with the character count.
        """
        logging.info("Received message: %s", message)
        reply_text = f"Received {len(message.message)} characters."
        reply_message = AirlinkSMSMessage(phone_number=message.phone_number, message=reply_text)
        reply_client(reply_message)
        return True

    async with create_message_handler(
        remote_addr=remote_addr,
        remote_port=remote_port,
        local_bind_addr=local_bind_addr,
        local_bind_port=local_bind_port or remote_port,
    ) as airlink:
        logging.info("Started Airlink SMS listener context...")
        async for message in airlink.messages:
            on_message_received(message, airlink.send)

    logging.warning("Airlink SMS listener shut down.")


if __name__ == "__main__":
    main(_anyio_backend="asyncio")
