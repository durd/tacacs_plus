# TACACS+ over TLS (RFC 9887) against the test server, with certificates from
# the tls_certs fixture in conftest.py.

import os
import socket
import ssl
import struct
import subprocess
import sys
import threading

import pytest

from tacacs_plus.async_client import TACACSClient as AsyncTACACSClient
from tacacs_plus.client import TACACSClient
from tacacs_plus.exceptions import TACACSProtocolError
from tacacs_plus.flags import (
    TAC_PLUS_AUTHEN_CHPASS, TAC_PLUS_AUTHEN_TYPE_CHAP, TAC_PLUS_AUTHEN_TYPE_PAP,
    TAC_PLUS_UNENCRYPTED_FLAG
)
from tacacs_plus.tls import check_tls, tls_context

from .tacacs_server import TacacsServer

USERS = {'alice': 'secret', 'bob': 'expired'}


@pytest.fixture
def server(server_tls):
    srv = TacacsServer(None, dict(USERS), error_users=['bob'], tls=server_tls)
    yield srv
    srv.close()


def client(srv, tls_certs, cls=TACACSClient, **kwargs):
    if 'tls' not in kwargs:
        kwargs['tls'] = tls_context(cafile=tls_certs['ca'])
    return cls('127.0.0.1', srv.port, None, timeout=5, **kwargs)


def test_ascii_login(server, tls_certs):
    assert client(server, tls_certs).authenticate('alice', 'secret').valid
    assert client(server, tls_certs).authenticate('alice', 'wrong').invalid
    request = server.requests[-1]
    assert request['tls'] and request['flags'] & TAC_PLUS_UNENCRYPTED_FLAG


def test_expired_password_and_change_password(server, tls_certs):
    r = client(server, tls_certs).authenticate('bob', 'expired')
    assert r.getdata and r.aborted
    assert client(server, tls_certs).authenticate('bob', 'expired', new_password='new1').valid
    assert client(server, tls_certs).change_password('alice', 'secret', 'new2').valid
    assert server.requests[-1]['action'] == TAC_PLUS_AUTHEN_CHPASS
    assert client(server, tls_certs).authenticate('alice', 'new2').valid


@pytest.mark.parametrize('authen_type', [TAC_PLUS_AUTHEN_TYPE_PAP, TAC_PLUS_AUTHEN_TYPE_CHAP])
def test_pap_and_chap(server, tls_certs, authen_type):
    r = client(server, tls_certs).authenticate('alice', 'secret', authen_type=authen_type,
                                               chap_ppp_id='A', chap_challenge='0123456789abcdef')
    assert r.valid


@pytest.mark.asyncio
async def test_async(server, tls_certs):
    cli = client(server, tls_certs, cls=AsyncTACACSClient)
    assert (await cli.authenticate('alice', 'secret')).valid
    assert (await cli.authenticate('bob', 'expired', new_password='new1')).valid
    assert (await cli.change_password('alice', 'secret', 'new2')).valid
    assert all(r['flags'] & TAC_PLUS_UNENCRYPTED_FLAG for r in server.requests)


def test_client_certificate(server_tls, tls_certs):
    server_tls.verify_mode = ssl.CERT_REQUIRED
    srv = TacacsServer(None, dict(USERS), tls=server_tls)
    try:
        with pytest.raises(OSError):  # the server rejects the handshake
            client(srv, tls_certs).authenticate('alice', 'secret')
        tls = tls_context(cafile=tls_certs['ca'], certfile=tls_certs['client'],
                          keyfile=tls_certs['client_key'])
        assert client(srv, tls_certs, tls=tls).authenticate('alice', 'secret').valid
    finally:
        srv.close()


def test_unknown_ca(server):
    """The system CAs don't know the test CA."""
    with pytest.raises(ssl.SSLCertVerificationError):
        client(server, {}, tls=tls_context()).authenticate('alice', 'secret')


def test_wrong_server_name(server, tls_certs):
    with pytest.raises(ssl.SSLCertVerificationError):
        client(server, tls_certs, tls_server_name='tacacs.example.com').authenticate('alice', 'secret')
    # the certificate is for 127.0.0.1 and localhost
    assert client(server, tls_certs, tls_server_name='localhost').authenticate('alice', 'secret').valid


def test_tls12_server_refused(tls_certs):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(tls_certs['server'], tls_certs['server_key'])
    srv = TacacsServer(None, dict(USERS), tls=context)
    try:
        with pytest.raises(ssl.SSLError):
            client(srv, tls_certs).authenticate('alice', 'secret')
    finally:
        srv.close()


def test_obfuscated_reply_over_tls(server_tls, tls_certs):
    """A reply without the unencrypted flag over TLS is a protocol error."""
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()

    def serve():
        conn, _ = listener.accept()
        with server_tls.wrap_socket(conn, server_side=True) as tls_conn:
            header = tls_conn.recv(12)
            tls_conn.recv(struct.unpack('!I', header[8:])[0])
            body = struct.pack('!BBHH', 1, 0, 0, 0)
            # same version, type and session_id, seq_no 2, flags 0 (obfuscated)
            tls_conn.sendall(header[:2] + b'\x02\x00' + header[4:8] + struct.pack('!I', len(body)) + body)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        cli = TACACSClient('127.0.0.1', listener.getsockname()[1], None, timeout=5,
                           tls=tls_context(cafile=tls_certs['ca']))
        with pytest.raises(TACACSProtocolError, match='obfuscated'):
            cli.authenticate('alice', 'secret')
    finally:
        thread.join(5)
        listener.close()


def test_check_tls():
    check_tls(None, 'secret')  # no TLS: anything goes
    check_tls(tls_context(), None)
    with pytest.raises(ValueError, match='secret=None'):
        TACACSClient('127.0.0.1', 49, 'secret', tls=tls_context())
    old = ssl.create_default_context()
    old.minimum_version = ssl.TLSVersion.TLSv1_2
    with pytest.raises(ValueError, match='TLS 1.3'):
        TACACSClient('127.0.0.1', 49, None, tls=old)
    unverified = tls_context()
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    with pytest.raises(ValueError, match='verified'):
        AsyncTACACSClient('127.0.0.1', 49, None, tls=unverified)
    with pytest.raises(TypeError):
        TACACSClient('127.0.0.1', 49, None, tls=True)


@pytest.mark.parametrize('cls', [TACACSClient, AsyncTACACSClient])
def test_default_port(cls):
    """port=None means 49, or 6049 (Cisco ISE's TLS port) with TLS."""
    assert cls('127.0.0.1', None, 'secret').port == 49
    assert cls('127.0.0.1', None, None, tls=tls_context()).port == 6049
    assert cls('127.0.0.1', 300, None, tls=tls_context()).port == 300


@pytest.mark.asyncio
async def test_async_without_secret_sets_unencrypted_flag():
    """Without a secret the async client didn't set the flag, so servers de-obfuscated garbage."""
    srv = TacacsServer(None, dict(USERS))
    try:
        cli = AsyncTACACSClient('127.0.0.1', srv.port, None, timeout=5)
        assert (await cli.authenticate('alice', 'secret')).valid
        assert srv.requests[-1]['flags'] & TAC_PLUS_UNENCRYPTED_FLAG
    finally:
        srv.close()


def test_cli(server, tls_certs):
    """With --tls-ca the CLI uses TLS and asks for no shared key (stdin is closed)."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {k: v for k, v in os.environ.items() if k != 'TACACS_PLUS_KEY'}
    env['PYTHONPATH'] = root
    result = subprocess.run(
        [sys.executable, os.path.join(root, 'bin', 'tacacs_client'), '-H', '127.0.0.1',
         '-p', str(server.port), '--tls-ca', tls_certs['ca'], '-u', 'alice', '-v',
         'authenticate', '-p', 'secret'],
        env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert 'status: PASS' in result.stdout
    assert server.requests[-1]['tls']
