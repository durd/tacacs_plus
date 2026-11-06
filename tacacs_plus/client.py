import socket
import secrets
import select
import logging
import contextlib


from .flags import (
    TAC_PLUS_MAJOR_VER, TAC_PLUS_MINOR_VER, TAC_PLUS_PRIV_LVL_MIN,
    TAC_PLUS_AUTHEN_TYPE_CHAP, TAC_PLUS_AUTHEN_TYPE_PAP,
    TAC_PLUS_AUTHEN, TAC_PLUS_AUTHEN_TYPE_ASCII, TAC_PLUS_AUTHEN_METH_TACACSPLUS,
    TAC_PLUS_AUTHOR, TAC_PLUS_AUTHOR_STATUS_FAIL, TAC_PLUS_PRIV_LVL_MAX,
    TAC_PLUS_ACCT, TAC_PLUS_VIRTUAL_REM_ADDR, TAC_PLUS_VIRTUAL_PORT,
    TAC_PLUS_CONTINUE_FLAG_ABORT, TAC_PLUS_AUTHEN_CHPASS, TAC_PLUS_UNENCRYPTED_FLAG
)
from .authen_dialog import AuthenDialog, start_data
from .exceptions import TACACSProtocolError
from .tls import check_tls
from .packet import TACACSPacket, TACACSHeader
from .authentication import (
    TACACSAuthenticationStart, TACACSAuthenticationContinue, TACACSAuthenticationReply
)
from .authorization import TACACSAuthorizationStart, TACACSAuthorizationReply
from .accounting import TACACSAccountingStart, TACACSAccountingReply

logger = logging.getLogger(__name__)



class TACACSClient:
    """
    A TACACS+ client for authentication, authorization and accounting.
    https://www.rfc-editor.org/rfc/rfc8907

    An open source TACACS+ server daemon is available at
    http://www.shrubbery.net/tac_plus/
    """

    def __init__(self, host, port, secret, timeout=10, session_id=None,
                 family=socket.AF_INET, version_max=TAC_PLUS_MAJOR_VER,
                 version_min=TAC_PLUS_MINOR_VER, tls=None, tls_server_name=None):
        """
        :param host:        hostname or address of the TACACS+ server
        :param port:        port of the TACACS+ server, generally 49
        :param secret:      the secret key used to obfuscate packet bodies; can
                            be `None` to disable packet body obfuscation, and
                            must be `None` with `tls`
        :param timeout:     seconds to wait for the connection and each reply
        :param session_id:  a 32-bit int used as session_id for every
                            session; leave it empty (the default) so each
                            session gets a new random one
        :param family:      socket.AF_INET or socket.AF_INET6
        :param version_max: TACACS+ major version number, 12
        :param version_min: TACACS+ minor version number, 0 or 1
        :param tls:         an ssl.SSLContext for TACACS+ over TLS (RFC 9887),
                            see tacacs_plus.tls.tls_context(); `port` is then
                            the server's TLS port
        :param tls_server_name: the name the server's certificate must match
                            (and SNI); default `host`
        """
        self._sock = None
        self.host = host
        self.port = port
        self.secret = secret
        self.timeout = timeout
        self.version_max = version_max
        self.version_min = version_min
        self.family = family
        check_tls(tls, secret)
        self.tls = tls
        self.tls_server_name = tls_server_name

        # the minor version for sessions other than PAP/CHAP authentication
        self._version_min = version_min
        self._session_id = session_id
        self._new_session()

    @property
    def version(self):
        return (self.version_max * 0x10) + self.version_min

    def _new_session(self, version_min=None):
        """
        Prepare a new session (one connection): a new session_id and the
        minor version, so nothing carries over from an earlier session.

        RFC 8907 (section 4.1) wants a cryptographically random session_id.
        It also matters for security: the obfuscation pad depends only on
        session_id, secret, version and seq_no (section 4.5), so two sessions
        with the same session_id get the same pad, and XOR-ing their packets
        cancels it.  A session_id given to __init__ is used for every session.
        """
        self.session_id = self._session_id or secrets.randbelow(2 ** 32 - 1) + 1
        self.version_min = self._version_min if version_min is None else version_min

    @property
    def sock(self):
        if not self._sock:  # pragma: nocover
            conn = (self.host, self.port)
            if self.family == socket.AF_INET6:
                # For AF_INET6 address family, a four-tuple (host, port,
                # flowinfo, scopeid) is used
                conn = (self.host, self.port, 0, 0)
            self._sock = socket.socket(self.family, socket.SOCK_STREAM)
            self._sock.setblocking(1)
            self._sock.settimeout(self.timeout)
            self._sock.connect(conn)
            if self.tls is not None:
                # the handshake uses the timeout set above
                self._sock = self.tls.wrap_socket(
                    self._sock, server_hostname=self.tls_server_name or self.host)
        return self._sock

    @contextlib.contextmanager
    def closing(self):
        try:
            self.sock
            yield
        finally:
            if self._sock:
                self._sock.close()
                self._sock = None

    def send(self, body, req_type, seq_no=1, expect_reply=True):
        """
        Send one TACACS+ packet and read the server's reply.

        :param body:     a packet body object with `packed` bytes, e.g.
                         TACACSAuthenticationStart
        :param req_type: TAC_PLUS_AUTHEN,
                         TAC_PLUS_AUTHOR,
                         TAC_PLUS_ACCT
        :param seq_no:   The sequence number of the current packet.  The
                         first packet in a session MUST have the sequence
                         number 1 and each subsequent packet will increment
                         the sequence number by one.  Thus clients only send
                         packets containing odd sequence numbers, and TACACS+
                         servers only send packets containing even sequence
                         numbers.
        :param expect_reply: False to return without reading a reply, e.g.
                         after TAC_PLUS_CONTINUE_FLAG_ABORT
        :return:         TACACSPacket, or None if `expect_reply` is False
        :raises:         TimeoutError, OSError (TACACSProtocolError for a
                         reply that isn't TACACS+)
        """
        # construct a packet
        header = TACACSHeader(
            self.version,
            req_type,
            self.session_id,
            len(body.packed),
            seq_no=seq_no,
            flags=(0 if self.secret else TAC_PLUS_UNENCRYPTED_FLAG)
        )
        packet = TACACSPacket(header, body.packed, self.secret)

        logger.debug('%s\nsent header <%s>\nsent body <%s>',
                     body.__class__.__name__, header, body)
        self.sock.send(bytes(packet))
        if not expect_reply:
            return None

        # with TLS, decrypted data can wait in the SSL buffer, where select()
        # doesn't see it
        pending = self.tls is not None and self.sock.pending()
        readable = pending or select.select([self.sock], [], [], self.timeout)[0]
        if readable:
            # TACACS+ header packets are always 12 bytes
            header_bytes = self._recv_exactly(12)
            resp_header = TACACSHeader.unpacked(header_bytes)
            # If the reply header doesn't match, it's likely a non-TACACS+ TCP
            # service answering with data we don't antipicate.  Bail out.
            if any([
                resp_header.version_max != header.version_max,
                resp_header.type != header.type,
                resp_header.session_id != header.session_id
            ]):
                logger.error('%s\nrecv header <%s>\n%s',
                             resp_header.__class__.__name__, resp_header,
                             resp_header.packed)
                raise TACACSProtocolError(
                    f'unexpected reply header <{resp_header}>')
            # RFC 9887: over TLS, packets must not be obfuscated
            if self.tls is not None and not resp_header.flags & TAC_PLUS_UNENCRYPTED_FLAG:
                raise TACACSProtocolError('obfuscated reply over TLS')

            # read the number of bytes specified in the response header
            body_bytes = self._recv_exactly(resp_header.length)
            return TACACSPacket(
                resp_header,
                body_bytes,
                self.secret
            )
        raise TimeoutError

    def _recv_exactly(self, size):
        """
        Read `size` bytes; recv() may return fewer, and returns none once the
        server has closed the connection.
        """
        data = b''
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise TACACSProtocolError(
                    f'connection closed after {len(data)} of {size} bytes')
            data += chunk
        return data

    def authenticate(self, username, password=None, priv_lvl=TAC_PLUS_PRIV_LVL_MIN,
                     authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII,
                     chap_ppp_id=None, chap_challenge=None,
                     rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR, port=TAC_PLUS_VIRTUAL_PORT,
                     new_password=None, prompt=None, max_steps=10,
                     encoding='latin-1'):
        """
        Authenticate to a TACACS+ server with a username and password.

        With TAC_PLUS_AUTHEN_TYPE_ASCII the server leads a dialog of
        GETUSER/GETPASS/GETDATA replies, which are answered from `username`,
        `password` and `new_password` (see AuthenDialog).  When an answer
        is missing, `prompt` is asked; without `prompt` the client aborts the
        session and returns the unanswered reply with `reply.aborted` set, so
        the caller can collect the answer (e.g. a new password) and retry.

        :param username:
        :param password:       the user's (current) password
        :param priv_lvl:       privilege level the user asks for, 0-15
        :param authen_type:    TAC_PLUS_AUTHEN_TYPE_ASCII,
                               TAC_PLUS_AUTHEN_TYPE_PAP,
                               TAC_PLUS_AUTHEN_TYPE_CHAP
        :param chap_ppp_id:    with TAC_PLUS_AUTHEN_TYPE_CHAP: the PPP ID, a
                               1-character string
        :param chap_challenge: with TAC_PLUS_AUTHEN_TYPE_CHAP: the challenge, a
                               string of up to 255 characters (latin-1, so
                               each character is one byte)
        :param rem_addr:       AAA request source, default to TAC_PLUS_VIRTUAL_REM_ADDR
        :param port:           AAA port, default to TAC_PLUS_VIRTUAL_PORT
        :param new_password:   answer when the server asks for a new password
                               (ASCII only, e.g. an expired password)
        :param prompt:         optional callable `prompt(server_msg, echo)`
                               returning the answer as a string, or None to
                               abort; used when no answer is known
        :param max_steps:      maximum number of CONTINUE packets sent
        :param encoding:       encoding of usernames and passwords on the wire
        :return:               TACACSAuthenticationReply
        :raises:               TimeoutError, OSError (TACACSProtocolError
                               for a reply that isn't TACACS+),
                               ValueError
        """
        if (authen_type in (TAC_PLUS_AUTHEN_TYPE_PAP, TAC_PLUS_AUTHEN_TYPE_CHAP)
                and not password and prompt is not None):
            password = prompt(f'password for {username}: ', False)
        data, version_min = start_data(authen_type, password, chap_ppp_id,
                                       chap_challenge, encoding)
        self._new_session(version_min)
        with self.closing():
            packet = self.send(
                TACACSAuthenticationStart(username, authen_type, priv_lvl,
                                          data, rem_addr=rem_addr, port=port,
                                          encoding=encoding),
                TAC_PLUS_AUTHEN
            )
            reply = self._authen_reply(packet)
            if authen_type == TAC_PLUS_AUTHEN_TYPE_ASCII:
                reply = self._authen_dialog(packet, reply, username, password,
                                            new_password, prompt, max_steps,
                                            encoding)

        return reply

    def change_password(self, username, old_password=None, new_password=None,
                        priv_lvl=TAC_PLUS_PRIV_LVL_MIN,
                        rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR,
                        port=TAC_PLUS_VIRTUAL_PORT, prompt=None, max_steps=10,
                        encoding='latin-1'):
        """
        Change a user's password with an ASCII TAC_PLUS_AUTHEN_CHPASS session.

        The server asks for the old and the new password (usually twice) in a
        GETPASS/GETDATA dialog, answered like in `authenticate`.

        :param username:
        :param old_password:
        :param new_password:
        :param priv_lvl:
        :param rem_addr:       AAA request source, default to TAC_PLUS_VIRTUAL_REM_ADDR
        :param port:           AAA port, default to TAC_PLUS_VIRTUAL_PORT
        :param prompt:         see `authenticate`
        :param max_steps:      maximum number of CONTINUE packets sent
        :param encoding:       encoding of usernames and passwords on the wire
        :return:               TACACSAuthenticationReply
        :raises:               TimeoutError, OSError (TACACSProtocolError
                               for a reply that isn't TACACS+)
        """
        self._new_session()
        with self.closing():
            packet = self.send(
                TACACSAuthenticationStart(username, TAC_PLUS_AUTHEN_TYPE_ASCII,
                                          priv_lvl, rem_addr=rem_addr, port=port,
                                          action=TAC_PLUS_AUTHEN_CHPASS,
                                          encoding=encoding),
                TAC_PLUS_AUTHEN
            )
            reply = self._authen_reply(packet)
            reply = self._authen_dialog(packet, reply, username, old_password,
                                        new_password, prompt, max_steps, encoding)
        return reply

    def _authen_reply(self, packet):
        reply = TACACSAuthenticationReply.unpacked(packet.body)
        logger.debug('%s\nrecv header <%s>\nrecv body <%s>',
                     reply.__class__.__name__, packet.header, reply)
        return reply

    def _authen_dialog(self, packet, reply, username, password, new_password,
                       prompt, max_steps, encoding):
        """
        Answer GETUSER/GETPASS/GETDATA replies until the server ends the
        dialog (PASS, FAIL, ERROR, ...), or abort it: see AuthenDialog.  When
        no answer is known and `prompt` gives none, or after `max_steps`
        CONTINUE packets, the client sends a CONTINUE with
        TAC_PLUS_CONTINUE_FLAG_ABORT and returns the unanswered reply with
        `aborted` set.
        """
        dialog = AuthenDialog(username, password, new_password, max_steps, encoding)
        while dialog.asks(reply):
            kind, answer = dialog.known_answer(reply)
            if answer is None and prompt is not None and dialog.steps_left:
                answer = prompt(dialog.server_msg(reply), not reply.noecho)
            if answer is None or not dialog.steps_left:
                self.send(
                    TACACSAuthenticationContinue(
                        '', flags=TAC_PLUS_CONTINUE_FLAG_ABORT),
                    TAC_PLUS_AUTHEN,
                    packet.seq_no + 1,
                    expect_reply=False
                )
                reply.aborted = True
                break

            dialog.answered(kind)
            packet = self.send(
                TACACSAuthenticationContinue(answer, encoding=encoding),
                TAC_PLUS_AUTHEN,
                packet.seq_no + 1
            )
            reply = self._authen_reply(packet)
        return reply

    def authorize(self, username, arguments=None,
                  authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII, priv_lvl=TAC_PLUS_PRIV_LVL_MIN,
                  rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR, port=TAC_PLUS_VIRTUAL_PORT):
        """
        Authorize with a TACACS+ server.

        :param username:
        :param arguments:      AV pairs as bytes, e.g. [b'service=shell',
                               b'cmd=show', b'cmd-arg=version']
        :param authen_type:    TAC_PLUS_AUTHEN_TYPE_ASCII,
                               TAC_PLUS_AUTHEN_TYPE_PAP,
                               TAC_PLUS_AUTHEN_TYPE_CHAP
        :param priv_lvl:       minimal required privilege level; if the server
                               answers with a lower priv-lvl, the reply's
                               status is set to TAC_PLUS_AUTHOR_STATUS_FAIL
        :param rem_addr:       AAA request source, default to TAC_PLUS_VIRTUAL_REM_ADDR
        :param port:           AAA port, default to TAC_PLUS_VIRTUAL_PORT
        :return:               TACACSAuthorizationReply
        :raises:               TimeoutError, OSError (TACACSProtocolError
                               for a reply that isn't TACACS+)
        """
        self._new_session()
        with self.closing():
            packet = self.send(
                TACACSAuthorizationStart(username,
                                         TAC_PLUS_AUTHEN_METH_TACACSPLUS,
                                         priv_lvl, authen_type, arguments or [],
                                         rem_addr=rem_addr, port=port),
                TAC_PLUS_AUTHOR
            )
            reply = TACACSAuthorizationReply.unpacked(packet.body)
            logger.debug('%s\nrecv header <%s>\nrecv body <%s>',
                         reply.__class__.__name__, packet.header, reply)
            reply_arguments = dict([
                arg.split(b'=', 1)
                for arg in reply.arguments or []
                if arg.find(b'=') > -1]
            )
            user_priv_lvl = int(reply_arguments.get(
                b'priv-lvl', TAC_PLUS_PRIV_LVL_MAX))
            if user_priv_lvl < priv_lvl:
                reply.status = TAC_PLUS_AUTHOR_STATUS_FAIL
        return reply

    def account(self, username, flags, arguments=None,
                authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII, priv_lvl=TAC_PLUS_PRIV_LVL_MIN,
                rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR, port=TAC_PLUS_VIRTUAL_PORT):
        """
        Account with a TACACS+ server.

        :param username:
        :param flags:          TAC_PLUS_ACCT_FLAG_START,
                               TAC_PLUS_ACCT_FLAG_WATCHDOG,
                               TAC_PLUS_ACCT_FLAG_STOP
        :param arguments:      AV pairs as bytes, e.g. [b'service=shell',
                               b'cmd=show', b'cmd-arg=version']
        :param authen_type:    TAC_PLUS_AUTHEN_TYPE_ASCII,
                               TAC_PLUS_AUTHEN_TYPE_PAP,
                               TAC_PLUS_AUTHEN_TYPE_CHAP
        :param priv_lvl:       the user's privilege level
        :param rem_addr:       AAA request source, default to TAC_PLUS_VIRTUAL_REM_ADDR
        :param port:           AAA port, default to TAC_PLUS_VIRTUAL_PORT
        :return:               TACACSAccountingReply
        :raises:               TimeoutError, OSError (TACACSProtocolError
                               for a reply that isn't TACACS+)
        """
        self._new_session()
        with self.closing():
            packet = self.send(
                TACACSAccountingStart(username, flags,
                                      TAC_PLUS_AUTHEN_METH_TACACSPLUS,
                                      priv_lvl, authen_type, arguments or [],
                                      rem_addr=rem_addr, port=port),
                TAC_PLUS_ACCT
            )
            reply = TACACSAccountingReply.unpacked(packet.body)
            logger.debug('%s\nrecv header <%s>\nrecv body <%s>',
                         reply.__class__.__name__, packet.header, reply)
        return reply
