# aioairlinksms

An asyncio Python library for sending and receiving SMS messages via Sierra/Semtech Airlink modems.

This library presently supports the UDP based protocol only and does not support SMS over the USB -> serial interface.

## Installation

This project uses [Poetry](https://python-poetry.org/) for dependency management. To install the project and dependencies, run:

```bash
poetry install
```
or 
```
pip install .
```

## Usage

This project provides a command-line interface for testing the functionality of this library, receiving SMS messages and replying with the character count of the received message.

```bash
aioairlinksms [OPTIONS]
```

### Options

- `--remote-addr TEXT`: Remote address to send messages to
- `--remote-port INTEGER`: Remote port to send messages to
- `--local-bind-addr TEXT`: Local address to bind the listening server to. (Default: 0.0.0.0)
- `--local-bind-port INTEGER`: Local port to bind the listening server to.
- `-v`, `--verbose`: Enable verbose logging.
- `--help`: Show this message and exit.

## Example

To connect to a modem at 192.168.43.1 that is listening on port 8000 and replying on port 8001, run:

```bash
airlinksms --remote-addr 192.168.43.1 --remote-port 8000 --local-bind-port 8001 --verbose
```

## Exceptions

This package defines and raises several custom exceptions to handle error conditions:

- **AirlinkConnectionClosedError**  
  Raised when attempting to send a message after the UDP client socket has been closed.

- **AirlinkSMSMessageDecodeError**  
  Raised when a message cannot be decoded from the Airlink SMS format, such as invalid delimiters, incorrect field count, unsupported data type, or malformed hex encoding.

- **AirlinkSMSMessageEncodeError**  
  Raised when a message cannot be encoded for sending, such as exceeding the maximum allowed length.

These exceptions are defined in `aioairlinksms.exceptions` and are used throughout the UDP client/server and message serialization/deserialization logic.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
