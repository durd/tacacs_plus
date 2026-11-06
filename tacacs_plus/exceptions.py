class TACACSProtocolError(OSError):
    """
    The server's reply isn't a TACACS+ reply for this session: a header that
    doesn't match the request, or a connection closed in the middle of a
    packet.

    A subclass of OSError, which `socket.error` is an alias of, so code that
    catches those still catches this.
    """
