"""
Custom exceptions for PyOdin
"""


class OdinException(Exception):
    """Base exception for all Odin errors"""
    
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class OdinConnectionError(OdinException):
    """Raised when connection to device fails"""
    pass


class OdinFirmwareError(OdinException):
    """Raised when firmware parsing/loading fails"""
    pass


class OdinVerificationError(OdinException):
    """Raised when signature/hash verification fails"""
    pass


class OdinUSBError(OdinException):
    """Raised when USB communication fails"""
    pass


class OdinProtocolError(OdinException):
    """Raised when protocol communication fails"""
    pass


class OdinInvalidDataError(OdinException):
    """Raised when invalid data is encountered"""
    pass


class OdinTimeoutError(OdinException):
    """Raised when operation times out"""
    pass





