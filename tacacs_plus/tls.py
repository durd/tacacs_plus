"""
TACACS+ over TLS (RFC 9887).

Pass an ssl.SSLContext as `tls` to either client, and `secret=None`: with TLS,
packet bodies must not be obfuscated (the TAC_PLUS_UNENCRYPTED_FLAG is set
instead), and TLS 1.3 or newer is required.  tls_context() builds a suitable
context.  With `port=None` the clients connect to TLS_PORT, 6049, the port
Cisco ISE uses by default; RFC 9887 registers TCP port 300 ("tacacss"), which
some servers use instead.
"""
import ssl

#: the port for TACACS+ without TLS (RFC 8907)
PORT = 49
#: the port for TACACS+ over TLS that Cisco ISE uses by default
TLS_PORT = 6049


def default_port(port, tls):
    """
    `port`, or if it is None, TLS_PORT with `tls` and PORT without.
    """
    if port is not None:
        return port
    return TLS_PORT if tls is not None else PORT


def tls_context(cafile=None, capath=None, cadata=None, certfile=None,
                keyfile=None, password=None):
    """
    An ssl.SSLContext for TACACS+ over TLS: TLS 1.3 or newer, and the
    server's certificate and hostname verified.

    Example::

        from tacacs_plus.client import TACACSClient
        from tacacs_plus.tls import tls_context

        tls = tls_context(cafile='tacacs-ca.pem')
        cli = TACACSClient('tacacs.example.com', 6049, None, tls=tls)
        reply = cli.authenticate('alice', 'password')

    RFC 9887 also asks for revocation checking, which Python's ssl module
    does only with CRLs you load yourself: call
    `context.load_verify_locations(crl_file)` and set
    `context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF` (or
    VERIFY_CRL_CHECK_CHAIN).  OCSP isn't supported.

    :param cafile:   PEM file with the CA certificate(s) that signed the
                     server's certificate; with no cafile, capath or cadata,
                     the system's CAs are used
    :param capath:   directory of CA certificates, see
                     ssl.SSLContext.load_verify_locations
    :param cadata:   CA certificate(s) as a PEM string or DER bytes
    :param certfile: the client's certificate (PEM), for servers that ask for
                     one; may also contain the key
    :param keyfile:  the client certificate's private key, if not in certfile
    :param password: password for the private key, if it is encrypted
    :return:         ssl.SSLContext
    """
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH, cafile=cafile, capath=capath, cadata=cadata)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if certfile:
        context.load_cert_chain(certfile, keyfile, password)
    return context


def check_tls(context, secret):
    """
    Check that `context` can be used for TACACS+ over TLS with `secret`.

    :raises: TypeError if `context` isn't an ssl.SSLContext, ValueError if a
             secret is given, TLS versions before 1.3 are allowed or the
             server's certificate isn't verified
    """
    if context is None:
        return
    if not isinstance(context, ssl.SSLContext):
        raise TypeError('tls must be an ssl.SSLContext, see tacacs_plus.tls.tls_context()')
    if secret is not None:
        raise ValueError('with TLS, packets are not obfuscated (RFC 9887): pass secret=None')
    if context.minimum_version < ssl.TLSVersion.TLSv1_3:
        raise ValueError('TACACS+ over TLS needs TLS 1.3 or newer (RFC 9887): set '
                         'minimum_version = ssl.TLSVersion.TLSv1_3, or use tls_context()')
    if context.verify_mode != ssl.CERT_REQUIRED:
        raise ValueError("the server's certificate must be verified (verify_mode CERT_REQUIRED)")
