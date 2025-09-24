class AirlinkConnectionClosedError(Exception):
    """Exception class raised when there is an attempt to send an Airlink message using a closed socket"""


class AirlinkSMSMessageError(ValueError):
    """Exception class for all errors related to processing of airlink messages"""


class AirlinkSMSMessageEncodeError(AirlinkSMSMessageError):
    """Exception class for encoding failures of Airlink SMS messages"""


class AirlinkSMSMessageDecodeError(AirlinkSMSMessageError):
    """Exception class for decoding failures of Airlink SMS messages"""
