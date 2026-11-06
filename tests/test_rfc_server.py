# End-to-end tests over TCP against the RFC 8907 test server in tacacs_server.py.
# They check the protocol (obfuscation, sequence numbers, the ASCII dialog), not
# how Cisco ISE behaves; see the server's docstring.

import asyncio
import os
import socket
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
        # without a new password the dialog is aborted at the server's question
        # (which used to be turned into FAIL because the prompt has NOECHO set)
        r = await cli.authenticate('bob', 'expired')
        assert r.getdata and r.noecho and r.aborted
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


def async_client(srv, timeout=5):
    return AsyncTACACSClient('127.0.0.1', srv.port, SECRET, timeout=timeout)


@pytest.mark.asyncio
async def test_async_expired_password_and_change_password(server, encoding):
    new = new_password(encoding)
    r = await async_client(server).authenticate('bob', 'expired', new_password=new, encoding=encoding)
    assert r.valid and r.server_msg == b'Password changed'
    assert (await async_client(server).authenticate('bob', new, encoding=encoding)).valid
    r = await async_client(server).change_password('alice', 'g\xe5mla', new, encoding=encoding)
    assert r.valid
    assert server.requests[-1]['action'] == TAC_PLUS_AUTHEN_CHPASS
    assert (await async_client(server).authenticate('alice', new, encoding=encoding)).valid


@pytest.mark.asyncio
@pytest.mark.parametrize('authen_type', [TAC_PLUS_AUTHEN_TYPE_PAP, TAC_PLUS_AUTHEN_TYPE_CHAP])
async def test_async_pap_and_chap_encoding(server, encoding, authen_type):
    r = await async_client(server).authenticate('alice', 'g\xe5mla', authen_type=authen_type,
                                                chap_ppp_id='A', chap_challenge='0123456789abcdef',
                                                encoding=encoding)
    assert r.valid


@pytest.mark.asyncio
@pytest.mark.parametrize('coroutine', [False, True])
async def test_async_prompt(server, coroutine):
    asked = []

    def answer(msg, echo):
        asked.append((msg, echo))
        return 'newpw'

    async def answer_async(msg, echo):
        await asyncio.sleep(0)
        return answer(msg, echo)

    r = await async_client(server).authenticate('bob', 'expired',
                                                prompt=answer_async if coroutine else answer)
    assert r.valid
    assert asked == [('Enter new password: ', False), ('Confirm new password: ', False)]


@pytest.mark.asyncio
async def test_async_pap_without_password():
    with pytest.raises(ValueError):
        await AsyncTACACSClient('127.0.0.1', 49, SECRET).authenticate(
            'alice', authen_type=TAC_PLUS_AUTHEN_TYPE_PAP)


@pytest.mark.asyncio
async def test_async_read_timeout():
    """A server that accepts but never answers; reads used to wait forever."""
    silent = socket.socket()
    silent.bind(('127.0.0.1', 0))
    silent.listen()
    try:
        cli = AsyncTACACSClient('127.0.0.1', silent.getsockname()[1], SECRET, timeout=0.3)
        with pytest.raises(TimeoutError):
            await cli.authenticate('alice', 'secret')
    finally:
        silent.close()


@pytest.fixture
def aaa_server():
    srv = TacacsServer(SECRET, {'alice': 'secret'}, authorizations={
        'alice': [b'priv-lvl=15', b'role=admin'],
        'bob': [b'priv-lvl=1'],
    })
    yield srv
    srv.close()


def test_authorize(aaa_server):
    reply = client(aaa_server).authorize('alice', arguments=[b'service=shell', b'cmd='])
    assert reply.valid
    assert reply.arguments == [b'priv-lvl=15', b'role=admin']
    assert aaa_server.requests[-1]['arguments'] == [b'service=shell', b'cmd=']
    assert client(aaa_server).authorize('nobody', arguments=[b'service=shell']).invalid


def test_authorize_needs_priv_lvl(aaa_server):
    """The client turns a pass with a lower priv-lvl than asked for into FAIL."""
    assert client(aaa_server).authorize('bob', arguments=[b'service=shell'], priv_lvl=15).invalid
    assert client(aaa_server).authorize('bob', arguments=[b'service=shell'], priv_lvl=1).valid


def test_account(aaa_server):
    from tacacs_plus.flags import TAC_PLUS_ACCT_FLAG_START, TAC_PLUS_ACCT_FLAG_STOP
    args = [b'task_id=42', b'service=shell', b'cmd=show version']
    assert client(aaa_server).account('alice', TAC_PLUS_ACCT_FLAG_START, arguments=args).valid
    assert client(aaa_server).account('alice', TAC_PLUS_ACCT_FLAG_STOP, arguments=args).valid
    assert [(a['flags'], a['arguments']) for a in aaa_server.accounting] == [
        (TAC_PLUS_ACCT_FLAG_START, args), (TAC_PLUS_ACCT_FLAG_STOP, args)]


@pytest.mark.asyncio
async def test_async_authorize_and_account(aaa_server):
    from tacacs_plus.flags import TAC_PLUS_ACCT_FLAG_START
    cli = async_client(aaa_server)
    reply = await cli.authorize('alice', arguments=[b'service=shell'])
    assert reply.valid and b'role=admin' in reply.arguments
    assert (await cli.account('alice', TAC_PLUS_ACCT_FLAG_START, arguments=[b'task_id=1'])).valid


@pytest.mark.parametrize('call', ['authenticate', 'authorize', 'account'])
def test_wrong_secret_is_a_protocol_error(aaa_server, call):
    """The reply de-obfuscates to garbage; that used to come back as e.g. status 'UNKNOWN: 151'."""
    from tacacs_plus.exceptions import TACACSProtocolError
    from tacacs_plus.flags import TAC_PLUS_ACCT_FLAG_START
    cli = TACACSClient('127.0.0.1', aaa_server.port, 'not-the-secret', timeout=5)
    for _ in range(20):  # each session's garbage is different
        with pytest.raises(TACACSProtocolError, match='wrong shared secret'):
            if call == 'authenticate':
                cli.authenticate('alice', 'secret')
            elif call == 'authorize':
                cli.authorize('alice', arguments=[b'service=shell'])
            else:
                cli.account('alice', TAC_PLUS_ACCT_FLAG_START, arguments=[b'task_id=1'])


@pytest.mark.asyncio
async def test_async_wrong_secret_is_a_protocol_error(aaa_server):
    from tacacs_plus.exceptions import TACACSProtocolError
    cli = AsyncTACACSClient('127.0.0.1', aaa_server.port, 'not-the-secret', timeout=5)
    for _ in range(20):
        with pytest.raises(TACACSProtocolError, match='wrong shared secret'):
            await cli.authenticate('alice', 'secret')
