import random
import socket
import select
import logging
import contextlib
import re
from hashlib import md5


from .flags import (
    TAC_PLUS_MAJOR_VER, TAC_PLUS_MINOR_VER, TAC_PLUS_PRIV_LVL_MIN,
    TAC_PLUS_AUTHEN_TYPE_CHAP, TAC_PLUS_MINOR_VER_ONE, TAC_PLUS_AUTHEN_TYPE_PAP,
    TAC_PLUS_AUTHEN, TAC_PLUS_AUTHEN_TYPE_ASCII, TAC_PLUS_AUTHEN_METH_TACACSPLUS,
    TAC_PLUS_AUTHOR, TAC_PLUS_AUTHOR_STATUS_FAIL, TAC_PLUS_PRIV_LVL_MAX,
    TAC_PLUS_ACCT, TAC_PLUS_VIRTUAL_REM_ADDR, TAC_PLUS_VIRTUAL_PORT,
    TAC_PLUS_CONTINUE_FLAG_ABORT, TAC_PLUS_AUTHEN_CHPASS
)
from .exceptions import TACACSProtocolError
from .packet import TACACSPacket, TACACSHeader
from .authentication import (
    TACACSAuthenticationStart, TACACSAuthenticationContinue, TACACSAuthenticationReply,
    to_bytes
)
from .authorization import TACACSAuthorizationStart, TACACSAuthorizationReply
from .accounting import TACACSAccountingStart, TACACSAccountingReply

logger = logging.getLogger(__name__)

# prompt texts in GETPASS/GETDATA replies, see TACACSClient._prompt_kind
PASSWORD_PROMPT = re.compile(r'pass|secret|\bpin\b', re.I)
NEW_PASSWORD_PROMPT = re.compile(r'\bnew\b|confirm|re-?enter|re-?type|again|verify', re.I)
OLD_PASSWORD_PROMPT = re.compile(r'\bold\b|current|existing', re.I)
USER_PROMPT = re.compile(r'user|login', re.I)


class TACACSClient:
    """
    A TACACS+ authentication client.
    https://datatracker.ietf.org/doc/draft-ietf-opsawg-tacacs

    An open source TACACS+ server daemon is available at
    http://www.shrubbery.net/tac_plus/
    """

    def __init__(self, host, port, secret, timeout=10, session_id=None,
                 family=socket.AF_INET, version_max=TAC_PLUS_MAJOR_VER,
                 version_min=TAC_PLUS_MINOR_VER):
        """
        :param host:        hostname of the TACACS+ server
        :param port:        port of the TACACS+ server, generally 49
        :param secret:      the secret key used to obfuscate packet bodies; can
                            be `None` to disable packet body obfuscation
        :param session_id:  a unique 32-bit int representing the session; if
                            left empty, one will be auto-generated
        :param version_max: TACACS+ major version number, 12
        :param version_min: TACACS+ minor version number, 0 or 1
        """
        self._sock = None
        self.host = host
        self.port = port
        self.secret = secret
        self.timeout = timeout
        self.version_max = version_max
        self.version_min = version_min
        self.family = family

        # session_id is an unsigned 32-bit int; unless it's provided, randomize
        self.session_id = session_id or random.randint(1, 2 ** 32 - 1)

    @property
    def version(self):
        return (self.version_max * 0x10) + self.version_min

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
        Send a TACACS+ message body

        :param body:     packed bytes, i.e., `struct.pack(...)`
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
            flags=(0 if self.secret else 1)
        )
        packet = TACACSPacket(header, body.packed, self.secret)

        logger.debug('%s\nsent header <%s>\nsent body <%s>',
                     body.__class__.__name__, header, body)
        self.sock.send(bytes(packet))
        if not expect_reply:
            return None

        readable, _, _ = select.select([self.sock], [], [], self.timeout)
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

    # how often each kind of answer is sent before the client gives up on the
    # dialog: the password twice (login, then an explicit "old password" when
    # it must be changed), the new password twice (new + confirmation)
    ANSWER_LIMITS = {'user': 1, 'old': 2, 'new': 2}

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
        `password` and `new_password` (see `_authen_dialog`).  When an answer
        is missing, `prompt` is asked; without `prompt` the client aborts the
        session and returns the unanswered reply with `reply.aborted` set, so
        the caller can collect the answer (e.g. a new password) and retry.

        :param username:
        :param password:
        :param priv_lvl:
        :param authen_type:    TAC_PLUS_AUTHEN_TYPE_ASCII,
                               TAC_PLUS_AUTHEN_TYPE_PAP,
                               TAC_PLUS_AUTHEN_TYPE_CHAP
        :param chap_ppp_id:    PPP ID when authen_type == 'chap'
        :param chap_challenge: challenge value when authen_type == 'chap'
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
        start_data = b''
        if authen_type in (TAC_PLUS_AUTHEN_TYPE_PAP,
                           TAC_PLUS_AUTHEN_TYPE_CHAP):
            self.version_min = TAC_PLUS_MINOR_VER_ONE
            if not password and prompt is not None:
                password = prompt(f'password for {username}: ', False)
            if not password:
                raise ValueError('a password is required for PAP and CHAP')

            if authen_type == TAC_PLUS_AUTHEN_TYPE_PAP:
                start_data = to_bytes(password, encoding)

            if authen_type == TAC_PLUS_AUTHEN_TYPE_CHAP:
                if not isinstance(chap_ppp_id, str):
                    raise ValueError('chap_ppp_id must be a string')
                if len(chap_ppp_id) != 1:
                    raise ValueError('chap_ppp_id must be a 1-byte string')
                if not isinstance(chap_challenge, str):
                    raise ValueError('chap_challenge must be a string')
                if len(chap_challenge) > 255:
                    raise ValueError('chap_challenge may not be more 255 bytes')
                start_data = (
                    to_bytes(chap_ppp_id) +
                    to_bytes(chap_challenge) +
                    md5(
                        to_bytes(chap_ppp_id) +
                        to_bytes(password, encoding) +
                        to_bytes(chap_challenge)
                    ).digest()
                )
        with self.closing():
            packet = self.send(
                TACACSAuthenticationStart(username, authen_type, priv_lvl,
                                          start_data, rem_addr=rem_addr, port=port,
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
        dialog (PASS, FAIL, ERROR, ...), or abort it.

        Each reply is answered with the username, the (old) password or the
        new password, see `_prompt_kind`.  Each kind is sent at most
        ANSWER_LIMITS times.  When no answer is known and `prompt` gives none,
        or after `max_steps` CONTINUE packets, the client sends a CONTINUE with
        TAC_PLUS_CONTINUE_FLAG_ABORT and returns the unanswered reply with
        `aborted` set.
        """
        values = {'user': username, 'old': password, 'new': new_password}
        sent = {'user': 0, 'old': 0, 'new': 0}
        steps = 0
        while reply.getuser or reply.getpass or reply.getdata:
            server_msg = reply.server_msg.decode(encoding, 'replace')
            kind = self._prompt_kind(reply, server_msg, sent)
            answer = None
            if kind and sent[kind] < self.ANSWER_LIMITS[kind]:
                answer = values[kind]
            if answer is None and prompt is not None and steps < max_steps:
                answer = prompt(server_msg, not reply.noecho)
            if answer is None or steps >= max_steps:
                self.send(
                    TACACSAuthenticationContinue(
                        '', flags=TAC_PLUS_CONTINUE_FLAG_ABORT),
                    TAC_PLUS_AUTHEN,
                    packet.seq_no + 1,
                    expect_reply=False
                )
                reply.aborted = True
                break

            if kind:
                sent[kind] += 1
            steps += 1
            packet = self.send(
                TACACSAuthenticationContinue(answer, encoding=encoding),
                TAC_PLUS_AUTHEN,
                packet.seq_no + 1
            )
            reply = self._authen_reply(packet)
        return reply

    @staticmethod
    def _prompt_kind(reply, server_msg, sent):
        """
        Guess what the server asks for: 'user', 'old' (the current password),
        'new' (a new password or its confirmation) or None (unknown).

        Password prompts are told apart by their text ("new", "confirm",
        "old", ...); when the text doesn't say, the first one is the current
        password and later ones the new password.
        """
        if reply.getuser:
            return 'user'
        if reply.getpass or reply.noecho or PASSWORD_PROMPT.search(server_msg):
            if NEW_PASSWORD_PROMPT.search(server_msg):
                return 'new'
            if OLD_PASSWORD_PROMPT.search(server_msg):
                return 'old'
            return 'old' if not sent['old'] else 'new'
        if USER_PROMPT.search(server_msg):
            return 'user'
        return None

    def authorize(self, username, arguments=[],
                  authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII, priv_lvl=TAC_PLUS_PRIV_LVL_MIN,
                  rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR, port=TAC_PLUS_VIRTUAL_PORT):
        """
        Authorize with a TACACS+ server.

        :param username:
        :param arguments:      The authorization arguments
        :param authen_type:    TAC_PLUS_AUTHEN_TYPE_ASCII,
                               TAC_PLUS_AUTHEN_TYPE_PAP,
                               TAC_PLUS_AUTHEN_TYPE_CHAP
        :param priv_lvl:       Minimal Required priv_lvl.
        :param rem_addr:       AAA request source, default to TAC_PLUS_VIRTUAL_REM_ADDR
        :param port:           AAA port, default to TAC_PLUS_VIRTUAL_PORT
        :return:               TACACSAuthenticationReply
        :raises:               TimeoutError, OSError (TACACSProtocolError
                               for a reply that isn't TACACS+)
        """
        with self.closing():
            packet = self.send(
                TACACSAuthorizationStart(username,
                                         TAC_PLUS_AUTHEN_METH_TACACSPLUS,
                                         priv_lvl, authen_type, arguments,
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

    def account(self, username, flags, arguments=[],
                authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII, priv_lvl=TAC_PLUS_PRIV_LVL_MIN,
                rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR, port=TAC_PLUS_VIRTUAL_PORT):
        """
        Account with a TACACS+ server.

        :param username:
        :param flags:          TAC_PLUS_ACCT_FLAG_START,
                               TAC_PLUS_ACCT_FLAG_WATCHDOG,
                               TAC_PLUS_ACCT_FLAG_STOP
        :param arguments:      The authorization arguments
        :param authen_type:    TAC_PLUS_AUTHEN_TYPE_ASCII,
                               TAC_PLUS_AUTHEN_TYPE_PAP,
                               TAC_PLUS_AUTHEN_TYPE_CHAP
        :param priv_lvl:       Minimal Required priv_lvl.
        :param rem_addr:       AAA request source, default to TAC_PLUS_VIRTUAL_REM_ADDR
        :param port:           AAA port, default to TAC_PLUS_VIRTUAL_PORT
        :return:               TACACSAccountingReply
        :raises:               TimeoutError, OSError (TACACSProtocolError
                               for a reply that isn't TACACS+)
        """
        with self.closing():
            packet = self.send(
                TACACSAccountingStart(username, flags,
                                      TAC_PLUS_AUTHEN_METH_TACACSPLUS,
                                      priv_lvl, authen_type, arguments,
                                      rem_addr=rem_addr, port=port),
                TAC_PLUS_ACCT
            )
            reply = TACACSAccountingReply.unpacked(packet.body)
            logger.debug('%s\nrecv header <%s>\nrecv body <%s>',
                         reply.__class__.__name__, packet.header, reply)
        return reply
