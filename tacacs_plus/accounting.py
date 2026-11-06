import io
import struct

from .flags import (
    TAC_PLUS_AUTHEN_SVC_LOGIN, TAC_PLUS_ACCT_STATUS_SUCCESS,
    TAC_PLUS_ACCT_STATUS_ERROR, TAC_PLUS_ACCT_STATUS_FOLLOW,
    TAC_PLUS_VIRTUAL_PORT, TAC_PLUS_VIRTUAL_REM_ADDR
)
from .packet import check_reply, to_bytes


class TACACSAccountingStart:

    def __init__(self, username, flags, authen_method, priv_lvl, authen_type,
                 arguments, rem_addr=TAC_PLUS_VIRTUAL_REM_ADDR,
                 port=TAC_PLUS_VIRTUAL_PORT):
        self.username = username
        self.flags = flags
        self.authen_method = authen_method
        self.priv_lvl = priv_lvl
        self.authen_type = authen_type
        self.service = TAC_PLUS_AUTHEN_SVC_LOGIN
        self.arguments = arguments
        self.rem_addr = rem_addr
        self.port = port

    @property
    def packed(self):
        #  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        # +----------------+----------------+----------------+----------------+
        # |      flags     |  authen_method |    priv_lvl    |  authen_type   |
        # +----------------+----------------+----------------+----------------+
        # | authen_service |    user_len    |    port_len    |  rem_addr_len  |
        # +----------------+----------------+----------------+----------------+
        # |    arg_cnt     |   arg_1_len    |   arg_2_len    |      ...       |
        # +----------------+----------------+----------------+----------------+
        # |   arg_N_len    |    user ...
        # +----------------+----------------+----------------+----------------+
        # |   port ...
        # +----------------+----------------+----------------+----------------+
        # |   rem_addr ...
        # +----------------+----------------+----------------+----------------+
        # |   arg_1 ...
        # +----------------+----------------+----------------+----------------+
        # |   arg_2 ...
        # +----------------+----------------+----------------+----------------+
        # |   ...
        # +----------------+----------------+----------------+----------------+
        # |   arg_N ...
        # +----------------+----------------+----------------+----------------+
        username = to_bytes(self.username)
        rem_addr = to_bytes(self.rem_addr)
        port = to_bytes(self.port)
        arguments = self.arguments
        body = struct.pack(
            'B' * 9,
            self.flags,
            self.authen_method,
            self.priv_lvl,
            self.authen_type,
            self.service,
            len(username),
            len(port),
            len(rem_addr),
            len(arguments),
        )
        for value in arguments:
            body += struct.pack('B', len(value))
        for value in (username, port, rem_addr):
            body += struct.pack(f'{len(value)}s', value)
        for value in arguments:
            body += struct.pack(f'{len(value)}s', value)
        return body

    def __str__(self):
        args = ', '.join([x.decode('utf-8') for x in self.arguments])
        return ', '.join([
            f'args: {args}',
            f'args_cnt: {len(self.arguments)}',
            f'authen_method: {self.authen_method}',
            f'authen_type: {self.authen_type}',
            f'authen_service: {self.service}',
            f'flags: {self.flags}',
            f'port_len: {len(self.port)}',
            f'port: {self.port}',
            f'priv_lvl: {self.priv_lvl}',
            f'rem_addr_len: {len(self.rem_addr)}',
            f'user: {self.username}',
            f'user_len: {len(self.username)}',
        ])


class TACACSAccountingReply:
    def __init__(self, status, server_msg, data):
        self.status = status
        self.server_msg = server_msg
        self.data = data
        self.flags = None
        self.arguments = []

    STATUSES = (
        TAC_PLUS_ACCT_STATUS_SUCCESS, TAC_PLUS_ACCT_STATUS_ERROR, TAC_PLUS_ACCT_STATUS_FOLLOW,
    )

    @classmethod
    def unpacked(cls, raw, strict=False):
        """
        Parse a reply body.  With `strict`, raise TACACSProtocolError for a
        body that doesn't add up or has an unknown status, e.g. because the
        shared secret is wrong; the clients always use strict.
        """
        #  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        # +----------------+----------------+----------------+----------------+
        # |         server_msg len          |            data_len             |
        # +----------------+----------------+----------------+----------------+
        # |     status     |         server_msg ...
        # +----------------+----------------+----------------+----------------+
        # |     data ...
        # +----------------+

        # B = unsigned char
        # !H = network-order (big-endian) unsigned short
        if strict and len(raw) < 5:
            check_reply('accounting reply', None, (), 5, len(raw))
        body_length = len(raw)
        raw = io.BytesIO(raw)
        server_msg_len, data_len = struct.unpack('!HH', raw.read(4))
        status = struct.unpack('B', raw.read(1))[0]
        if strict:
            check_reply('accounting reply', status, cls.STATUSES,
                        5 + server_msg_len + data_len, body_length)
        server_msg = raw.read(server_msg_len)
        data = raw.read(data_len) if data_len else b''
        return cls(status, server_msg, data)

    @property
    def valid(self):
        return self.status == TAC_PLUS_ACCT_STATUS_SUCCESS

    @property
    def error(self):
        return self.status == TAC_PLUS_ACCT_STATUS_ERROR

    @property
    def follow(self):
        return self.status == TAC_PLUS_ACCT_STATUS_FOLLOW

    @property
    def human_status(self):
        return {
            TAC_PLUS_ACCT_STATUS_SUCCESS: 'SUCCESS',
            TAC_PLUS_ACCT_STATUS_ERROR: 'ERROR',
            TAC_PLUS_ACCT_STATUS_FOLLOW: 'FOLLOW'
        }.get(self.status, f'UNKNOWN: {self.status}')

    def __str__(self):
        return ', '.join([
            f'data: {self.data}',
            f'data_len: {len(self.data)}',
            f'server_msg: {self.server_msg}',
            f'server_msg_len: {len(self.server_msg)}',
            f'status: {self.human_status}',
        ])
