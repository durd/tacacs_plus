import io
import struct

from .flags import (
    TAC_PLUS_PRIV_LVL_MIN, TAC_PLUS_AUTHEN_LOGIN, TAC_PLUS_AUTHEN_SVC_LOGIN,
    TAC_PLUS_AUTHEN_STATUS_PASS, TAC_PLUS_AUTHEN_STATUS_FAIL, TAC_PLUS_AUTHEN_STATUS_ERROR,
    TAC_PLUS_AUTHEN_STATUS_GETPASS, TAC_PLUS_VIRTUAL_PORT, TAC_PLUS_VIRTUAL_REM_ADDR,
    TAC_PLUS_AUTHEN_STATUS_GETDATA, TAC_PLUS_AUTHEN_STATUS_GETUSER,
    TAC_PLUS_AUTHEN_STATUS_RESTART, TAC_PLUS_AUTHEN_STATUS_FOLLOW,
    TAC_PLUS_REPLY_FLAG_NOECHO, TAC_PLUS_AUTHEN_TYPE_PAP, TAC_PLUS_AUTHEN_TYPE_CHAP
)
from .packet import check_reply, to_bytes


class TACACSAuthenticationStart:

    def __init__(self, username, authen_type, priv_lvl=TAC_PLUS_PRIV_LVL_MIN,
                 data=b'', rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR,
                 port=TAC_PLUS_VIRTUAL_PORT, action=TAC_PLUS_AUTHEN_LOGIN,
                 encoding='latin-1'):
        self.username = username
        self.action = action
        self.priv_lvl = priv_lvl
        self.authen_type = authen_type
        self.service = TAC_PLUS_AUTHEN_SVC_LOGIN
        self.data = data
        self.rem_addr = rem_addr
        self.port = port
        self.encoding = encoding

    @property
    def packed(self):
        # 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        #
        # +----------------+----------------+----------------+----------------+
        # |    action      |    priv_lvl    |  authen_type   |     service    |
        # +----------------+----------------+----------------+----------------+
        # |    user len    |    port len    |  rem_addr len  |    data len    |
        # +----------------+----------------+----------------+----------------+
        # |    user ...
        # +----------------+----------------+----------------+----------------+
        # |    port ...
        # +----------------+----------------+----------------+----------------+
        # |    rem_addr ...
        # +----------------+----------------+----------------+----------------+
        # |    data...
        # +----------------+----------------+----------------+----------------+

        # B = unsigned char
        # s = char[]
        username = to_bytes(self.username, self.encoding)
        rem_addr = to_bytes(self.rem_addr, self.encoding)
        port = to_bytes(self.port, self.encoding)
        data = self.data
        body = struct.pack(
            'B' * 8,
            self.action,
            self.priv_lvl,
            self.authen_type,
            self.service,
            len(username),
            len(port),
            len(rem_addr),
            len(data),
        )
        for value in (username, port, rem_addr, data):
            body += struct.pack(f'{len(value)}s', value)
        return body

    @property
    def _data_for_log(self):
        # PAP data is the password; CHAP data holds an MD5 of the password and
        # the challenge, which can be brute-forced offline
        if self.authen_type in (TAC_PLUS_AUTHEN_TYPE_PAP, TAC_PLUS_AUTHEN_TYPE_CHAP):
            return '*' * len(self.data)
        return self.data

    def __str__(self):
        return ', '.join([
            f'action: {self.action}',
            f'authen_type: {self.authen_type}',
            f'authen_service: {self.service}',
            f'data: {self._data_for_log}',
            f'data_len: {len(self.data)}',
            f'priv_lvl: {self.priv_lvl}',
            f'port: {self.port}',
            f'port_len: {len(self.port)}',
            f'rem_addr: {self.rem_addr}',
            f'rem_addr_len: {len(self.rem_addr)}',
            f'user: {self.username}',
            f'user_len: {len(self.username)}'
        ])


class TACACSAuthenticationContinue:
    def __init__(self, password, data=b'', flags=0, encoding='latin-1'):
        self.password = password
        self.data = data
        self.flags = flags
        self.encoding = encoding

    @property
    def packed(self):
        # 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        #
        # +----------------+----------------+----------------+----------------+
        # |          user_msg len           |            data len             |
        # +----------------+----------------+----------------+----------------+
        # |     flags      |  user_msg ...
        # +----------------+----------------+----------------+----------------+
        # |    data ...
        # +----------------+

        # B = unsigned char
        # !H = network-order (big-endian) unsigned short
        # s = char[]
        password = to_bytes(self.password, self.encoding)
        data = self.data
        return (
            struct.pack('!H', len(password)) +
            struct.pack('!H', len(data)) +
            struct.pack('B', self.flags) +
            struct.pack(f'{len(password)}s', password) +
            struct.pack(f'{len(data)}s', data)
        )

    def __str__(self):
        return ', '.join([
            f'data_len: {len(self.data)}',
            f'flags: {self.flags}',
            f"user_msg: {'*' * len(self.password)}",
            f'user_msg_len: {len(self.password)}'
        ])


class TACACSAuthenticationReply:
    """
    An authentication REPLY from the server.

    `status` is one of the TAC_PLUS_AUTHEN_STATUS_* values; `valid`,
    `invalid`, `error`, `getuser`, `getpass` and `getdata` test for them.
    `server_msg` is the server's message or prompt as bytes, `noecho` tells
    whether the answer to a prompt should be hidden, and `aborted` is set
    when the client ended the session instead of answering this reply.

    Example::

        reply = cli.authenticate('alice', 'password')
        if reply.valid:
            ...                                   # signed in
        elif reply.aborted and reply.getdata:
            ...                                   # the server wants a new password
        elif reply.invalid:
            ...                                   # wrong username or password
        message = reply.server_msg.decode('utf-8', 'replace')
    """

    def __init__(self, status, flags, server_msg, data):
        self.status = status
        self.flags = flags
        self.server_msg = server_msg
        self.data = data
        self.arguments = []
        # set by the client when it ended the dialog with
        # TAC_PLUS_CONTINUE_FLAG_ABORT instead of answering this reply
        self.aborted = False

    STATUSES = (
        TAC_PLUS_AUTHEN_STATUS_PASS, TAC_PLUS_AUTHEN_STATUS_FAIL,
        TAC_PLUS_AUTHEN_STATUS_GETDATA, TAC_PLUS_AUTHEN_STATUS_GETUSER,
        TAC_PLUS_AUTHEN_STATUS_GETPASS, TAC_PLUS_AUTHEN_STATUS_RESTART,
        TAC_PLUS_AUTHEN_STATUS_ERROR, TAC_PLUS_AUTHEN_STATUS_FOLLOW,
    )

    @classmethod
    def unpacked(cls, raw, strict=False):
        """
        Parse a reply body.  With `strict`, raise TACACSProtocolError for a
        body that doesn't add up or has an unknown status, e.g. because the
        shared secret is wrong; the clients always use strict.
        """
        # 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        #
        # +----------------+----------------+----------------+----------------+
        # |     status     |      flags     |        server_msg len           |
        # +----------------+----------------+----------------+----------------+
        # |           data len              |        server_msg ...
        # +----------------+----------------+----------------+----------------+
        # |           data ...
        # +----------------+----------------+

        # B = unsigned char
        # !H = network-order (big-endian) unsigned short
        if strict and len(raw) < 6:
            check_reply('authentication reply', None, (), 6, len(raw))
        body_length = len(raw)
        raw = io.BytesIO(raw)
        status, flags = struct.unpack('BB', raw.read(2))
        server_msg_len, data_len = struct.unpack('!HH', raw.read(4))
        if strict:
            check_reply('authentication reply', status, cls.STATUSES,
                        6 + server_msg_len + data_len, body_length)
        server_msg = raw.read(server_msg_len)
        data = raw.read(data_len)
        return cls(status, flags, server_msg, data)

    @property
    def valid(self):
        return self.status == TAC_PLUS_AUTHEN_STATUS_PASS

    @property
    def invalid(self):
        return self.status == TAC_PLUS_AUTHEN_STATUS_FAIL

    @property
    def error(self):
        return self.status == TAC_PLUS_AUTHEN_STATUS_ERROR

    @property
    def getpass(self):
        return self.status == TAC_PLUS_AUTHEN_STATUS_GETPASS

    @property
    def getdata(self):
        return self.status == TAC_PLUS_AUTHEN_STATUS_GETDATA

    @property
    def getuser(self):
        return self.status == TAC_PLUS_AUTHEN_STATUS_GETUSER

    @property
    def noecho(self):
        return bool(self.flags & TAC_PLUS_REPLY_FLAG_NOECHO)

    @property
    def human_status(self):
        return {
            TAC_PLUS_AUTHEN_STATUS_PASS: 'PASS',
            TAC_PLUS_AUTHEN_STATUS_FAIL: 'FAIL',
            TAC_PLUS_AUTHEN_STATUS_GETPASS: 'GETPASS',
            TAC_PLUS_AUTHEN_STATUS_GETDATA: 'GETDATA',
            TAC_PLUS_AUTHEN_STATUS_GETUSER: 'GETUSER',
            TAC_PLUS_AUTHEN_STATUS_RESTART: 'RESTART',
            TAC_PLUS_AUTHEN_STATUS_ERROR: 'ERROR',
            TAC_PLUS_AUTHEN_STATUS_FOLLOW: 'FOLLOW'
        }.get(self.status, f'UNKNOWN: {self.status}')

    def __str__(self):
        return ', '.join([
            f'data: {self.data}',
            f'data_len: {len(self.data)}',
            f'flags: {self.flags}',
            f'server_msg: {self.server_msg}',
            f'server_msg_len: {len(self.server_msg)}',
            f'status: {self.human_status}'
        ])
