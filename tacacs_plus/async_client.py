import socket
import logging
import secrets
import contextlib
import inspect
import asyncio


from .flags import (
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_MINOR_VER,
    TAC_PLUS_PRIV_LVL_MIN,
    TAC_PLUS_AUTHEN_TYPE_CHAP,
    TAC_PLUS_AUTHEN_TYPE_PAP,
    TAC_PLUS_AUTHEN,
    TAC_PLUS_AUTHEN_TYPE_ASCII,
    TAC_PLUS_AUTHEN_METH_TACACSPLUS,
    TAC_PLUS_AUTHOR,
    TAC_PLUS_AUTHOR_STATUS_FAIL,
    TAC_PLUS_PRIV_LVL_MAX,
    TAC_PLUS_ACCT,
    TAC_PLUS_VIRTUAL_REM_ADDR,
    TAC_PLUS_VIRTUAL_PORT,
    TAC_PLUS_AUTHEN_CHPASS,
    TAC_PLUS_CONTINUE_FLAG_ABORT,
)
from .authen_dialog import AuthenDialog, start_data
from .exceptions import TACACSProtocolError
from .packet import TACACSPacket, TACACSHeader
from .authentication import (
    TACACSAuthenticationStart,
    TACACSAuthenticationContinue,
    TACACSAuthenticationReply,
)
from .authorization import TACACSAuthorizationStart, TACACSAuthorizationReply
from .accounting import TACACSAccountingStart, TACACSAccountingReply

logger = logging.getLogger(__name__)


async def _ask(prompt, *args):
    """Call `prompt`, which may be a plain function or a coroutine function."""
    answer = prompt(*args)
    if inspect.isawaitable(answer):
        answer = await answer
    return answer



class TACACSClient:
    """
    An asyncio TACACS+ client for authentication, authorization and accounting.
    https://www.rfc-editor.org/rfc/rfc8907

    The same API as tacacs_plus.client.TACACSClient, with coroutines.

    An open source TACACS+ server daemon is available at
    http://www.shrubbery.net/tac_plus/
    """

    def __init__(
        self,
        host,
        port,
        secret,
        timeout=10,
        session_id=None,
        family=socket.AF_INET,
        version_max=TAC_PLUS_MAJOR_VER,
        version_min=TAC_PLUS_MINOR_VER,
    ):
        """
        :param host:        hostname or address of the TACACS+ server
        :param port:        port of the TACACS+ server, generally 49
        :param secret:      the secret key used to obfuscate packet bodies; can
                            be None to disable packet body obfuscation
        :param timeout:     seconds to wait for the connection and each reply
        :param session_id:  a 32-bit int used as session_id for every
                            session; leave it empty (the default) so each
                            session gets a new random one
        :param family:      socket.AF_INET or socket.AF_INET6
        :param version_max: TACACS+ major version number, 12
        :param version_min: TACACS+ minor version number, 0 or 1
        """
        self.host = host
        self.port = port
        self.secret = secret
        self.timeout = timeout
        self.version_max = version_max
        self.version_min = version_min
        self.family = family

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

    @contextlib.asynccontextmanager
    async def flow_control(self):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, family=self.family),
                self.timeout)
        except asyncio.TimeoutError:
            # asyncio.TimeoutError is only the builtin TimeoutError from 3.11
            raise TimeoutError(f'no connection to {self.host}:{self.port}') from None
        try:
            yield reader, writer
        finally:
            writer.close()
            await writer.wait_closed()

    async def send(self, body, req_type, seq_no=1, reader=None, writer=None,
                   expect_reply=True):
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
        :param reader:   asyncio.StreamReader instance
        :param writer:   asyncio.StreamWriter instance
        :param expect_reply: False to return without reading a reply, e.g.
                         after TAC_PLUS_CONTINUE_FLAG_ABORT
        :return:         TACACSPacket, or None if `expect_reply` is False
        :raises:         TimeoutError, OSError (TACACSProtocolError for a
                         reply that isn't TACACS+)
        """
        if not reader or not writer:
            raise OSError('Working outside of context')
        # construct a packet
        header = TACACSHeader(
            self.version,
            req_type,
            self.session_id,
            len(body.packed),
            seq_no=seq_no,
        )
        packet = TACACSPacket(header, body.packed, self.secret)

        logger.debug('%s\nsent header <%s>\nsent body <%s>',
                     body.__class__.__name__, header, body)

        writer.write(bytes(packet))
        await writer.drain()
        if not expect_reply:
            return None

        # TACACS+ header packets are always 12 bytes
        header_bytes = await self._read_exactly(reader, 12, self.timeout)
        resp_header = TACACSHeader.unpacked(header_bytes)
        # If the reply header doesn't match, it's likely a non-TACACS+ TCP
        # service answering with data we don't antipicate.  Bail out.
        possible_errors = [
            resp_header.version_max != header.version_max,
            resp_header.type != header.type,
            resp_header.session_id != header.session_id,
        ]
        if any(possible_errors):
            logger.error('%s\nrecv header <%s>\n%s',
                         resp_header.__class__.__name__, resp_header,
                         resp_header.packed)
            raise TACACSProtocolError(
                f'unexpected reply header <{resp_header}>')

        # read the number of bytes specified in the response header
        body_bytes = await self._read_exactly(reader, resp_header.length, self.timeout)
        return TACACSPacket(resp_header, body_bytes, self.secret)

    @staticmethod
    async def _read_exactly(reader, size, timeout=None):
        """
        Read `size` bytes; read() may return fewer, and returns none once the
        server has closed the connection.  Each read waits at most `timeout`
        seconds.
        """
        data = b''
        while len(data) < size:
            try:
                chunk = await asyncio.wait_for(reader.read(size - len(data)), timeout)
            except asyncio.TimeoutError:
                raise TimeoutError(f'no reply after {len(data)} of {size} bytes') from None
            if not chunk:
                raise TACACSProtocolError(
                    f'connection closed after {len(data)} of {size} bytes')
            data += chunk
        return data

    async def authenticate(
        self,
        username,
        password=None,
        priv_lvl=TAC_PLUS_PRIV_LVL_MIN,
        authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII,
        chap_ppp_id=None,
        chap_challenge=None,
        rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR,
        port=TAC_PLUS_VIRTUAL_PORT,
        new_password=None,
        prompt=None,
        max_steps=10,
        encoding='latin-1',
    ):
        """
        Authenticate to a TACACS+ server with a username and password.

        Works like tacacs_plus.client.TACACSClient.authenticate, including the
        ASCII dialog; `prompt` may also be a coroutine function.

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
            password = await _ask(prompt, f'password for {username}: ', False)
        data, version_min = start_data(authen_type, password, chap_ppp_id,
                                       chap_challenge, encoding)
        self._new_session(version_min)
        async with self.flow_control() as (reader, writer):
            packet = await self.send(
                TACACSAuthenticationStart(
                    username,
                    authen_type,
                    priv_lvl,
                    data,
                    rem_addr=rem_addr,
                    port=port,
                    encoding=encoding,
                ),
                TAC_PLUS_AUTHEN,
                reader=reader,
                writer=writer,
            )
            reply = self._authen_reply(packet)
            if authen_type == TAC_PLUS_AUTHEN_TYPE_ASCII:
                reply = await self._authen_dialog(
                    packet, reply, reader, writer, username, password,
                    new_password, prompt, max_steps, encoding)

        return reply

    async def change_password(
        self,
        username,
        old_password=None,
        new_password=None,
        priv_lvl=TAC_PLUS_PRIV_LVL_MIN,
        rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR,
        port=TAC_PLUS_VIRTUAL_PORT,
        prompt=None,
        max_steps=10,
        encoding='latin-1',
    ):
        """
        Change a user's password with an ASCII TAC_PLUS_AUTHEN_CHPASS session,
        like tacacs_plus.client.TACACSClient.change_password.

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
        async with self.flow_control() as (reader, writer):
            packet = await self.send(
                TACACSAuthenticationStart(
                    username,
                    TAC_PLUS_AUTHEN_TYPE_ASCII,
                    priv_lvl,
                    rem_addr=rem_addr,
                    port=port,
                    action=TAC_PLUS_AUTHEN_CHPASS,
                    encoding=encoding,
                ),
                TAC_PLUS_AUTHEN,
                reader=reader,
                writer=writer,
            )
            reply = self._authen_reply(packet)
            reply = await self._authen_dialog(
                packet, reply, reader, writer, username, old_password,
                new_password, prompt, max_steps, encoding)
        return reply

    @staticmethod
    def _authen_reply(packet):
        reply = TACACSAuthenticationReply.unpacked(packet.body)
        logger.debug('%s\nrecv header <%s>\nrecv body <%s>',
                     reply.__class__.__name__, packet.header, reply)
        return reply

    async def _authen_dialog(self, packet, reply, reader, writer, username,
                             password, new_password, prompt, max_steps, encoding):
        """
        Answer the ASCII dialog like tacacs_plus.client.TACACSClient's
        _authen_dialog, see AuthenDialog.
        """
        dialog = AuthenDialog(username, password, new_password, max_steps, encoding)
        while dialog.asks(reply):
            kind, answer = dialog.known_answer(reply)
            if answer is None and prompt is not None and dialog.steps_left:
                answer = await _ask(prompt, dialog.server_msg(reply), not reply.noecho)
            if answer is None or not dialog.steps_left:
                await self.send(
                    TACACSAuthenticationContinue(
                        '', flags=TAC_PLUS_CONTINUE_FLAG_ABORT),
                    TAC_PLUS_AUTHEN,
                    packet.seq_no + 1,
                    reader,
                    writer,
                    expect_reply=False,
                )
                reply.aborted = True
                break

            dialog.answered(kind)
            packet = await self.send(
                TACACSAuthenticationContinue(answer, encoding=encoding),
                TAC_PLUS_AUTHEN,
                packet.seq_no + 1,
                reader,
                writer,
            )
            reply = self._authen_reply(packet)
        return reply

    async def authorize(
        self,
        username,
        arguments=None,
        authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII,
        priv_lvl=TAC_PLUS_PRIV_LVL_MIN,
        rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR,
        port=TAC_PLUS_VIRTUAL_PORT,
    ):
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
        if arguments is None:
            arguments = []
        self._new_session()
        async with self.flow_control() as (reader, writer):
            packet = await self.send(
                TACACSAuthorizationStart(
                    username,
                    TAC_PLUS_AUTHEN_METH_TACACSPLUS,
                    priv_lvl,
                    authen_type,
                    arguments,
                    rem_addr=rem_addr,
                    port=port,
                ),
                TAC_PLUS_AUTHOR,
                reader=reader,
                writer=writer,
            )
            reply = TACACSAuthorizationReply.unpacked(packet.body)

            logger.debug('%s\nrecv header <%s>\nrecv body <%s>',
                         reply.__class__.__name__, packet.header, reply)

            reply_arguments = dict(
                [
                    arg.split(b'=', 1)
                    for arg in reply.arguments or []
                    if arg.find(b'=') > -1
                ]
            )
            user_priv_lvl = reply_arguments.get(b'priv-lvl', TAC_PLUS_PRIV_LVL_MAX)
            user_priv_lvl = int(user_priv_lvl)
            if user_priv_lvl < priv_lvl:
                reply.status = TAC_PLUS_AUTHOR_STATUS_FAIL

            return reply

    async def account(
        self,
        username,
        flags,
        arguments=None,
        authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII,
        priv_lvl=TAC_PLUS_PRIV_LVL_MIN,
        rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR,
        port=TAC_PLUS_VIRTUAL_PORT,
    ):
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
        if arguments is None:
            arguments = []
        self._new_session()
        async with self.flow_control() as (reader, writer):
            packet = await self.send(
                TACACSAccountingStart(
                    username,
                    flags,
                    TAC_PLUS_AUTHEN_METH_TACACSPLUS,
                    priv_lvl,
                    authen_type,
                    arguments,
                    rem_addr=rem_addr,
                    port=port,
                ),
                TAC_PLUS_ACCT,
                reader=reader,
                writer=writer,
            )
            reply = TACACSAccountingReply.unpacked(packet.body)

            logger.debug('%s\nrecv header <%s>\nrecv body <%s>',
                         reply.__class__.__name__, packet.header, reply)

        return reply
