import shutil
import ssl
import subprocess

import pytest


def _openssl(*args, cwd):
    subprocess.run(['openssl', *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture(scope='session')
def tls_certs(tmp_path_factory):
    """
    A test CA and a server and client certificate signed by it, made with the
    openssl command (skipped if it isn't installed).  Returns a dict of file
    paths: ca, server, server_key, client, client_key.
    """
    if not shutil.which('openssl'):
        pytest.skip('openssl not installed')
    d = tmp_path_factory.mktemp('tls')
    for name in ('ca', 'server', 'client'):
        _openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256',
                 '-out', f'{name}.key', cwd=d)
    _openssl('req', '-x509', '-new', '-key', 'ca.key', '-out', 'ca.pem', '-days', '2',
             '-subj', '/CN=tacacs-test-ca',
             '-addext', 'basicConstraints=critical,CA:TRUE',
             '-addext', 'keyUsage=critical,keyCertSign,cRLSign', cwd=d)
    for name, usage, san in (('server', 'serverAuth', 'IP:127.0.0.1,DNS:localhost'),
                             ('client', 'clientAuth', 'DNS:client')):
        (d / f'{name}.ext').write_text(
            'basicConstraints=critical,CA:FALSE\n'
            'keyUsage=critical,digitalSignature\n'
            f'extendedKeyUsage={usage}\n'
            f'subjectAltName={san}\n'
            'authorityKeyIdentifier=keyid\n'
            'subjectKeyIdentifier=hash\n')
        _openssl('req', '-new', '-key', f'{name}.key', '-out', f'{name}.csr',
                 '-subj', f'/CN={name}', cwd=d)
        _openssl('x509', '-req', '-in', f'{name}.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
                 '-CAcreateserial', '-out', f'{name}.pem', '-days', '2',
                 '-extfile', f'{name}.ext', cwd=d)
    return {
        'ca': str(d / 'ca.pem'),
        'server': str(d / 'server.pem'), 'server_key': str(d / 'server.key'),
        'client': str(d / 'client.pem'), 'client_key': str(d / 'client.key'),
    }


@pytest.fixture
def server_tls(tls_certs):
    """A server-side TLS 1.3 context; set verify_mode to ask for client certificates."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(tls_certs['server'], tls_certs['server_key'])
    context.load_verify_locations(tls_certs['ca'])
    return context
