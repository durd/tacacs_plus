"""Minimal TACACS+ server for tests, written from RFC 8907 (not from the client library).

One authentication session per connection: PAP or CHAP (single START), or the ASCII
dialog (GETUSER/GETPASS/GETDATA) for login and change password (CHPASS). Users in
`error_users` get ERROR with PAP/CHAP and, with ASCII, "change password at next login"
prompts. Records what the client sent.

It checks that the client speaks the protocol (packet layout, obfuscation, sequence
numbers, CONTINUE and abort). It is not evidence of how Cisco ISE behaves: the prompt
texts and their order ("Password: ", "Enter new password: ", "Confirm new password: ")
are the same guesses the client makes, not taken from ISE.

Copied from durd/ise-cpp (tools/tacacs-probe branch); this repository has the main copy.
"""
import hashlib
import socket
import struct
import threading

AUTHEN = 0x01
LOGIN, CHPASS = 0x01, 0x02
ASCII, PAP, CHAP = 0x01, 0x02, 0x03
PASS, FAIL, GETDATA, GETUSER, GETPASS, ERROR = 0x01, 0x02, 0x03, 0x04, 0x05, 0x07
NOECHO = 0x01


def _pad(session_id, key, version, seq_no, length):
    """RFC 8907 section 4.5: body obfuscation pad."""
    pad, last = b'', b''
    while len(pad) < length:
        last = hashlib.md5(session_id + key + bytes([version, seq_no]) + last).digest()
        pad += last
    return pad[:length]


def _xor(data, pad):
    return bytes(a ^ b for a, b in zip(data, pad))


def _recv(conn, size):
    data = b''
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError('client closed')
        data += chunk
    return data


class TacacsServer:
    def __init__(self, secret, passwords, error_users=(), chpass=True, encoding='latin-1'):
        self.key = secret.encode()
        self.chpass = chpass                # False: answer CHPASS with ERROR
        self.encoding = encoding            # how passwords are expected on the wire
        self.passwords = passwords          # user -> password
        self.error_users = set(error_users)  # answered with ERROR (like ISE's "change at next login")
        self.requests = []                  # dicts with what each START contained
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    self._handle(conn)
                except (ConnectionError, struct.error, ValueError):
                    pass  # e.g. wrong shared secret: drop the connection, like ISE

    def _read(self, conn):
        header = _recv(conn, 12)
        version, ptype, seq_no, flags, session_id, length = struct.unpack('!BBBB4sI', header)
        body = _xor(_recv(conn, length), _pad(session_id, self.key, version, seq_no, length))
        return (version, ptype, seq_no, flags, session_id), body

    def _reply(self, conn, head, status, msg='', flags=0):
        version, ptype, seq_no, header_flags, session_id = head
        msg = msg.encode()
        reply = struct.pack('!BBHH', status, flags, len(msg), 0) + msg
        reply_seq = seq_no + 1
        header = struct.pack('!BBBB4sI', version, ptype, reply_seq, header_flags, session_id, len(reply))
        conn.sendall(header + _xor(reply, _pad(session_id, self.key, version, reply_seq, len(reply))))

    def _ask(self, conn, status, msg, flags=NOECHO):
        """Send a GET* reply and return the CONTINUE's user_msg (None if aborted)."""
        self._reply(conn, self._head, status, msg, flags)
        self._head, body = self._read(conn)
        msg_len, data_len, cont_flags = struct.unpack('!HHB', body[:5])
        self.prompts_answered.append(msg)
        return None if cont_flags & 0x01 else body[5:5 + msg_len]

    def _handle(self, conn):
        self._head, body = self._read(conn)
        action, priv_lvl, authen_type, service, user_len, port_len, addr_len, data_len = body[:8]
        rest = body[8:]
        user = rest[:user_len].decode(self.encoding)
        data = rest[user_len + port_len + addr_len:][:data_len]
        request = {'type': self._head[1], 'version': self._head[0], 'session_id': self._head[4], 'action': action, 'user': user, 'priv_lvl': priv_lvl, 'authen_type': authen_type}
        self.requests.append(request)
        self.prompts_answered = []
        if authen_type == PAP:
            password = self.passwords.get(user)
            status = FAIL
            if user in self.error_users:
                status = ERROR
            elif password is not None and password.encode(self.encoding) == data:
                status = PASS
            self._reply(conn, self._head, status)
            return
        if authen_type == CHAP:
            ppp_id, challenge, response = data[:1], data[1:-16], data[-16:]
            request.update(ppp_id=ppp_id, challenge=challenge)
            password = self.passwords.get(user)
            status = FAIL
            if user in self.error_users:
                status = ERROR
            elif password is not None and hashlib.md5(ppp_id + password.encode(self.encoding) + challenge).digest() == response:
                status = PASS
            self._reply(conn, self._head, status)
            return
        self._reply(conn, self._head, *self._ascii(conn, action, user))

    def _ascii(self, conn, action, user):
        if not user:
            user = (self._ask(conn, GETUSER, 'Username: ', flags=0) or b'').decode(self.encoding)
        if action == CHPASS and not self.chpass:
            return (ERROR, 'change password not supported')
        old = self._ask(conn, GETPASS, 'Old password: ' if action == CHPASS else 'Password: ')
        if old is None:
            return (FAIL, 'aborted')
        if self.passwords.get(user, '').encode(self.encoding) != old:
            return (FAIL, 'wrong password')
        if action == LOGIN and user not in self.error_users:
            return (PASS, '')
        new = self._ask(conn, GETDATA, 'Enter new password: ')
        if new is None:
            return (FAIL, 'aborted')
        confirm = self._ask(conn, GETDATA, 'Confirm new password: ')
        if confirm is None or confirm != new:
            return (FAIL, 'passwords differ')
        self.passwords[user] = new.decode(self.encoding)
        self.error_users.discard(user)
        return (PASS, 'Password changed')

    def close(self):
        self.sock.close()
