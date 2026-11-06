# Tests for the non-interactive ASCII login and change-password dialog.

from hashlib import md5
import io
import struct

import pytest

from tacacs_plus.flags import (
    TAC_PLUS_AUTHEN, TAC_PLUS_AUTHEN_LOGIN, TAC_PLUS_AUTHEN_CHPASS,
    TAC_PLUS_AUTHEN_TYPE_PAP, TAC_PLUS_AUTHEN_TYPE_CHAP,
    TAC_PLUS_AUTHEN_STATUS_PASS, TAC_PLUS_AUTHEN_STATUS_FAIL,
    TAC_PLUS_AUTHEN_STATUS_GETDATA, TAC_PLUS_AUTHEN_STATUS_GETUSER,
    TAC_PLUS_AUTHEN_STATUS_GETPASS, TAC_PLUS_REPLY_FLAG_NOECHO,
    TAC_PLUS_CONTINUE_FLAG_ABORT
)
from tacacs_plus.authentication import TACACSAuthenticationReply
from tacacs_plus.client import TACACSClient

SESSION_ID = 12345
NOECHO = TAC_PLUS_REPLY_FLAG_NOECHO


def reply(status, server_msg='', flags=0):
    """A server REPLY packet (unobfuscated) for the scripted socket."""
    server_msg = server_msg.encode('latin-1')
    body = struct.pack('!BBHH', status, flags, len(server_msg), 0) + server_msg
    header = struct.pack('!BBBBII', 0xc0, TAC_PLUS_AUTHEN, 2, 1, SESSION_ID, len(body))
    return header + body


class ScriptedSocket:
    """Replays server replies and records what the client sends."""

    def __init__(self, replies, fileobj):
        self.incoming = io.BytesIO(b''.join(replies))
        self.outgoing = io.BytesIO()
        self.fileobj = fileobj

    def send(self, data):
        self.outgoing.write(data)
        return len(data)

    def recv(self, size):
        return self.incoming.read(size)

    def fileno(self):
        # select.select() needs a real, readable file descriptor
        return self.fileobj.fileno()

    def close(self):
        pass

    def sent(self):
        """The bodies of the packets the client sent, in order."""
        self.outgoing.seek(0)
        bodies = []
        while True:
            header = self.outgoing.read(12)
            if not header:
                return bodies
            length = struct.unpack('!I', header[8:])[0]
            bodies.append(self.outgoing.read(length))

    def continues(self):
        """(user_msg, flags) of each CONTINUE the client sent."""
        result = []
        for body in self.sent()[1:]:
            user_msg_len, _, flags = struct.unpack('!HHB', body[:5])
            result.append((body[5:5 + user_msg_len], flags))
        return result


@pytest.fixture
def client(tmp_path):
    path = tmp_path / 'fake-socket'
    path.write_text('')
    fileobj = open(str(path))

    def make(*replies):
        c = TACACSClient('127.0.0.1', 49, None, session_id=SESSION_ID)
        c.script = ScriptedSocket(replies, fileobj)
        c._sock = c.script
        return c

    yield make
    fileobj.close()


def answers(c):
    return [msg for msg, _ in c.script.continues()]


def test_login_pass(client):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_GETPASS, 'Password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_PASS))
    r = c.authenticate('user', 'secret')
    assert r.valid and not r.aborted
    assert c.script.continues() == [(b'secret', 0)]


def test_login_fail_is_returned(client):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_GETPASS, 'Password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_FAIL, 'Bad password'))
    r = c.authenticate('user', 'wrong', new_password='new')
    assert r.invalid and not r.aborted
    assert r.server_msg == b'Bad password'
    assert answers(c) == [b'wrong']


def test_login_getpass_then_new_password(client):
    """GETPASS followed by GETDATA prompts: the case the old elif missed."""
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_GETPASS, 'Password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'Enter new password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'Confirm new password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_PASS))
    r = c.authenticate('user', 'old', new_password='new')
    assert r.valid
    assert answers(c) == [b'old', b'new', b'new']


def test_login_getdata_only(client):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'Password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'Password expired. New password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'Re-enter password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_PASS))
    r = c.authenticate('user', 'old', new_password='new')
    assert r.valid
    assert answers(c) == [b'old', b'new', b'new']


def test_login_prompts_without_text_go_by_order(client):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_GETPASS, '', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, '', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, '', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_PASS))
    r = c.authenticate('user', 'old', new_password='new')
    assert r.valid
    assert answers(c) == [b'old', b'new', b'new']


def test_login_explicit_old_password_after_login_password(client):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_GETPASS, 'Password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'Old password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'New password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'Retype new password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_PASS))
    r = c.authenticate('user', 'old', new_password='new')
    assert r.valid
    assert answers(c) == [b'old', b'old', b'new', b'new']


def test_login_new_password_needed_aborts(client):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_GETPASS, 'Password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'Enter new password: ', NOECHO))
    r = c.authenticate('user', 'old')
    assert r.getdata and r.aborted
    assert r.server_msg == b'Enter new password: '
    assert c.script.continues() == [(b'old', 0),
                                    (b'', TAC_PLUS_CONTINUE_FLAG_ABORT)]
    # the abort is not answered by the server, so nothing is left unread
    assert c.script.incoming.read() == b''


def test_login_no_password_aborts(client):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_GETPASS, 'Password: ', NOECHO))
    r = c.authenticate('user')
    assert r.getpass and r.aborted
    assert c.script.continues() == [(b'', TAC_PLUS_CONTINUE_FLAG_ABORT)]


def test_login_rejected_new_password_aborts(client):
    """The server asks again (e.g. policy): don't resend the same password."""
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_GETPASS, 'Password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'New password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'Confirm new password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'Too short. New password: ', NOECHO))
    r = c.authenticate('user', 'old', new_password='new')
    assert r.aborted
    assert r.server_msg == b'Too short. New password: '
    assert answers(c) == [b'old', b'new', b'new', b'']


def test_login_getuser(client):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_GETUSER, 'Username: '),
               reply(TAC_PLUS_AUTHEN_STATUS_GETPASS, 'Password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_PASS))
    r = c.authenticate('user', 'secret')
    assert r.valid
    assert answers(c) == [b'user', b'secret']


def test_login_unknown_prompt_aborts(client):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'Accept the terms (yes/no)? '))
    r = c.authenticate('user', 'secret')
    assert r.aborted
    assert answers(c) == [b'']


def test_login_prompt_callback(client):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_GETPASS, 'Password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'Accept the terms (yes/no)? '),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'New password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_PASS))
    asked = []

    def prompt(server_msg, echo):
        asked.append((server_msg, echo))
        return 'yes' if echo else 'typed'

    r = c.authenticate('user', 'old', prompt=prompt)
    assert r.valid
    assert asked == [('Accept the terms (yes/no)? ', True), ('New password: ', False)]
    assert answers(c) == [b'old', b'yes', b'typed']


def test_login_prompt_callback_returning_none_aborts(client):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_GETPASS, 'Password: ', NOECHO))
    r = c.authenticate('user', prompt=lambda msg, echo: None)
    assert r.aborted


def test_login_max_steps(client):
    c = client(*[reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'More? ')] * 4)
    r = c.authenticate('user', 'secret', prompt=lambda msg, echo: 'y', max_steps=3)
    assert r.getdata and r.aborted
    assert c.script.continues() == [(b'y', 0)] * 3 + [(b'', TAC_PLUS_CONTINUE_FLAG_ABORT)]


def test_change_password(client):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_GETPASS, 'Old password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'New password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_GETDATA, 'Retype new password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_PASS))
    r = c.change_password('user', 'old', 'new')
    assert r.valid
    start = c.script.sent()[0]
    assert start[0] == TAC_PLUS_AUTHEN_CHPASS
    assert answers(c) == [b'old', b'new', b'new']


def test_login_start_action(client):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_PASS))
    c.authenticate('user', 'secret')
    assert c.script.sent()[0][0] == TAC_PLUS_AUTHEN_LOGIN


@pytest.mark.parametrize('encoding, password, expected', [
    ('utf-8', '\xe5\xe4\xf6€', '\xe5\xe4\xf6€'.encode()),
    ('latin-1', '\xe5\xe4\xf6', b'\xe5\xe4\xf6'),
])
def test_login_encoding(client, encoding, password, expected):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_GETPASS, 'Password: ', NOECHO),
               reply(TAC_PLUS_AUTHEN_STATUS_PASS))
    c.authenticate('\xe5sa', password, encoding=encoding)
    assert answers(c) == [expected]
    assert '\xe5sa'.encode(encoding) in c.script.sent()[0]


def test_login_latin1_cannot_encode_euro(client):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_GETPASS, 'Password: ', NOECHO))
    with pytest.raises(UnicodeEncodeError):
        c.authenticate('user', '€')


def test_chap_encoding(client):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_PASS))
    c.authenticate('user', '€', authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP,
                   chap_ppp_id='A', chap_challenge='challenge', encoding='utf-8')
    digest = md5(b'A' + '€'.encode() + b'challenge').digest()
    assert c.script.sent()[0].endswith(digest)


def test_pap_without_password():
    c = TACACSClient('127.0.0.1', 49, None)
    with pytest.raises(ValueError):
        c.authenticate('user', authen_type=TAC_PLUS_AUTHEN_TYPE_PAP)


def test_pap_password_from_prompt(client):
    c = client(reply(TAC_PLUS_AUTHEN_STATUS_PASS))
    r = c.authenticate('user', authen_type=TAC_PLUS_AUTHEN_TYPE_PAP,
                       prompt=lambda msg, echo: 'typed')
    assert r.valid
    assert c.script.sent()[0].endswith(b'typed')


@pytest.mark.parametrize('flags, noecho', [(0x00, False), (0x01, True), (0x81, True), (0x80, False)])
def test_reply_noecho_is_a_bit_test(flags, noecho):
    raw = struct.pack('!BBHH', TAC_PLUS_AUTHEN_STATUS_GETPASS, flags, 0, 0)
    assert TACACSAuthenticationReply.unpacked(raw).noecho is noecho
