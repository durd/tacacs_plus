# End-to-end tests over TCP against the RFC 8907 test server in tacacs_server.py.
# They check the protocol (obfuscation, sequence numbers, the ASCII dialog), not
# how Cisco ISE behaves; see the server's docstring.

import os
import subprocess
import sys

import pytest

from tacacs_plus.async_client import TACACSClient as AsyncTACACSClient
from tacacs_plus.client import TACACSClient
from tacacs_plus.flags import (
    TAC_PLUS_AUTHEN_CHPASS, TAC_PLUS_AUTHEN_TYPE_CHAP, TAC_PLUS_AUTHEN_TYPE_PAP
)

from .tacacs_server import TacacsServer

SECRET = 'testing123'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(params=['latin-1', 'utf-8'])
def encoding(request):
    return request.param


@pytest.fixture
def server(encoding):
    srv = TacacsServer(SECRET, {'alice': 'g\xe5mla', 'bob': 'expired'},
                       error_users=['bob'], encoding=encoding)
    yield srv
    srv.close()


def client(srv):
    return TACACSClient('127.0.0.1', srv.port, SECRET, timeout=5)


def new_password(encoding):
    # the euro sign can't be encoded as latin-1
    return 'ny€1' if encoding == 'utf-8' else 'ny\xe41'


def test_ascii_login(server, encoding):
    assert client(server).authenticate('alice', 'g\xe5mla', encoding=encoding).valid
    r = client(server).authenticate('alice', 'wrong', encoding=encoding)
    assert r.invalid and r.server_msg == b'wrong password'


@pytest.mark.parametrize('authen_type', [TAC_PLUS_AUTHEN_TYPE_PAP, TAC_PLUS_AUTHEN_TYPE_CHAP])
def test_pap_and_chap(server, encoding, authen_type):
    def auth(user, password):
        return client(server).authenticate(user, password, authen_type=authen_type,
                                           chap_ppp_id='A', chap_challenge='0123456789abcdef',
                                           encoding=encoding)
    assert auth('alice', 'g\xe5mla').valid
    assert auth('alice', 'wrong').invalid
    assert auth('bob', 'expired').error  # what ISE answers for "change password at next login"


def test_expired_password_without_new_password(server, encoding):
    r = client(server).authenticate('bob', 'expired', encoding=encoding)
    assert r.getdata and r.aborted
    assert r.server_msg == b'Enter new password: '


def test_expired_password_with_new_password(server, encoding):
    new = new_password(encoding)
    r = client(server).authenticate('bob', 'expired', new_password=new, encoding=encoding)
    assert r.valid and r.server_msg == b'Password changed'
    assert client(server).authenticate('bob', new, encoding=encoding).valid


def test_change_password(server, encoding):
    new = new_password(encoding)
    r = client(server).change_password('alice', 'g\xe5mla', new, encoding=encoding)
    assert r.valid
    assert server.requests[-1]['action'] == TAC_PLUS_AUTHEN_CHPASS
    assert server.prompts_answered == ['Old password: ', 'Enter new password: ', 'Confirm new password: ']
    assert client(server).authenticate('alice', new, encoding=encoding).valid


def test_change_password_unsupported():
    srv = TacacsServer(SECRET, {'alice': 'old'}, chpass=False)
    try:
        assert client(srv).change_password('alice', 'old', 'new').error
    finally:
        srv.close()


def test_encoding_mismatch_fails():
    """A non-ASCII password only works when both sides use the same encoding."""
    srv = TacacsServer(SECRET, {'alice': 'g\xe5mla'}, encoding='utf-8')
    try:
        assert client(srv).authenticate('alice', 'g\xe5mla', encoding='latin-1').invalid
        assert client(srv).authenticate('alice', 'g\xe5mla', encoding='utf-8').valid
    finally:
        srv.close()


@pytest.mark.asyncio
async def test_async_client():
    srv = TacacsServer(SECRET, {'alice': 'secret', 'bob': 'expired'}, error_users=['bob'])
    try:
        cli = AsyncTACACSClient('127.0.0.1', srv.port, SECRET, timeout=5)
        assert (await cli.authenticate('alice', 'secret')).valid
        assert (await cli.authenticate('alice', 'secret', authen_type=TAC_PLUS_AUTHEN_TYPE_PAP)).valid
        # the async client has no dialog: it returns the server's next question,
        # which used to be turned into FAIL because the prompt has NOECHO set
        r = await cli.authenticate('bob', 'expired')
        assert r.getdata and r.noecho
    finally:
        srv.close()


def test_cli():
    srv = TacacsServer(SECRET, {'alice': 'secret'})
    try:
        def run(password):
            return subprocess.run(
                [sys.executable, os.path.join(ROOT, 'bin', 'tacacs_client'), '-H', '127.0.0.1',
                 '-p', str(srv.port), '-k', SECRET, '-u', 'alice', '-v', 'authenticate', '-p', password],
                env=dict(os.environ, PYTHONPATH=ROOT), stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=30)
        ok = run('secret')
        assert ok.returncode == 0 and 'status: PASS' in ok.stdout
        bad = run('wrong')
        assert bad.returncode == 1 and 'status: FAIL' in bad.stdout
    finally:
        srv.close()


def test_new_session_id_per_session(server, encoding):
    """Reusing a session_id repeats the obfuscation pad (RFC 8907 4.5)."""
    c = client(server)
    c.authenticate('alice', 'wrong', encoding=encoding)
    c.authenticate('bob', 'expired', encoding=encoding)
    c.change_password('alice', 'wrong', 'x', encoding=encoding)
    ids = [r['session_id'] for r in server.requests]
    assert len(ids) == 3 and len(set(ids)) == 3


def test_fixed_session_id(server):
    c = TACACSClient('127.0.0.1', server.port, SECRET, timeout=5, session_id=42)
    c.authenticate('alice', 'wrong')
    c.authenticate('alice', 'wrong')
    assert [r['session_id'] for r in server.requests] == [(42).to_bytes(4, 'big')] * 2


def test_minor_version_per_session(server):
    """PAP/CHAP use minor version 1; it must not stick for later sessions."""
    c = client(server)
    c.authenticate('alice', 'x', authen_type=TAC_PLUS_AUTHEN_TYPE_PAP)
    c.authenticate('alice', 'x')
    c.change_password('alice', 'x', 'y')
    assert [r['version'] for r in server.requests] == [0xc1, 0xc0, 0xc0]


@pytest.mark.asyncio
async def test_async_new_session_per_session():
    srv = TacacsServer(SECRET, {'alice': 'secret'})
    try:
        cli = AsyncTACACSClient('127.0.0.1', srv.port, SECRET, timeout=5)
        await cli.authenticate('alice', 'secret', authen_type=TAC_PLUS_AUTHEN_TYPE_PAP)
        await cli.authenticate('alice', 'secret')
        assert len({r['session_id'] for r in srv.requests}) == 2
        assert [r['version'] for r in srv.requests] == [0xc1, 0xc0]
    finally:
        srv.close()
