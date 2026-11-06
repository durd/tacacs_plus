class TACACSProtocolError(OSError):
    """
    The server's reply isn't a TACACS+ reply for this session: a header that
    doesn't match the request, a garbled body (usually a wrong shared
    secret), or a connection closed in the middle of a packet.

    Example::

        try:
            reply = cli.authenticate('alice', 'password')
        except TACACSProtocolError as e:
            print(e)   # e.g. "garbled authentication reply: ... (wrong shared secret?)"

    A subclass of OSError, which `socket.error` is an alias of, so code that
    catches those still catches this.
    """
