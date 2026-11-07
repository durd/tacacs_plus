TACACS+ over TLS
================

With TLS (RFC 9887) the connection is encrypted and the server is checked
against its certificate; there is no shared secret (pass ``None``).  You need
the CA certificate that signed the server's certificate, as a PEM file.

Cisco ISE uses port 6049 for TLS by default (and Cisco's IOS-XE examples set
``tls port 6049``); RFC 9887 registers port 300, which other servers may use.
Pass ``None`` as the port for the default: 6049 with TLS, 49 without.

.. tab-set::

   .. tab-item:: Without TLS

      .. code-block:: python

         from tacacs_plus.client import TACACSClient

         cli = TACACSClient('tacacs.example.com', 49, 'shared-secret')

   .. tab-item:: With TLS

      .. code-block:: python

         from tacacs_plus.client import TACACSClient
         from tacacs_plus.tls import tls_context

         tls = tls_context(cafile='tacacs-ca.pem')
         cli = TACACSClient('tacacs.example.com', 6049, None, tls=tls)

   .. tab-item:: With a client certificate

      .. code-block:: python

         from tacacs_plus.client import TACACSClient
         from tacacs_plus.tls import tls_context

         tls = tls_context(cafile='tacacs-ca.pem',
                           certfile='client.pem', keyfile='client.key')
         cli = TACACSClient('tacacs.example.com', 6049, None, tls=tls)

   .. tab-item:: By IP address

      .. code-block:: python

         from tacacs_plus.client import TACACSClient
         from tacacs_plus.tls import tls_context

         # the certificate is for tacacs.example.com, not for the address
         tls = tls_context(cafile='tacacs-ca.pem')
         cli = TACACSClient('192.0.2.10', 6049, None, tls=tls,
                            tls_server_name='tacacs.example.com')

Everything else (``authenticate``, ``change_password``, ...) works the same.  A
certificate problem raises ``ssl.SSLCertVerificationError``; its message says
what's wrong:

.. code-block:: python

   import ssl

   try:
       reply = cli.authenticate('alice', 'password')
   except ssl.SSLCertVerificationError as e:
       print(e.verify_message)   # e.g. "unable to get local issuer certificate"

.. _tls-ise:

Cisco ISE
---------

An ASCII login over TLS has been tested against ISE 3.4.  ISE needs more than
the server side of TLS:

- **A certificate for TACACS+.**  In ISE, a system certificate must have the
  *TACACS* usage.  Without one, ISE refuses every connection with
  ``TLSV1_ALERT_PROTOCOL_VERSION``, whatever TLS version the client offers.
- **A client certificate.**  ISE asks for one and fails with
  ``TLSV13_ALERT_CERTIFICATE_REQUIRED`` without it.  ISE must trust it, or the
  CA that signed it, under *Trusted Certificates* with *Trust for client
  authentication*.
- **The client's IP address in the certificate.**  ISE checks that the client
  certificate's subjectAltName contains the IP address the connection comes from,
  which is the network device's address in ISE.  Otherwise it fails with
  ``TLS_ALERT_BAD_CERTIFICATE``, and the TACACS live log says "SAN IP did not
  match".
- **A network device** for the client's address, with TACACS+ over TLS enabled.

These errors arrive as ``ssl.SSLError`` during the handshake or on the first
reply.  ISE's TACACS live log (*Operations > TACACS > Live Logs*) shows the step
that failed.

.. code-block:: python

   from tacacs_plus.client import TACACSClient
   from tacacs_plus.tls import tls_context

   # ise.pem: the CA that signed ISE's TACACS certificate (or that certificate,
   # if it is self-signed); client.pem has the client's IP in its subjectAltName
   tls = tls_context(cafile='ise.pem', certfile='client.pem', keyfile='client.key')
   cli = TACACSClient('ise.example.com', None, None, tls=tls)   # port 6049
   reply = cli.authenticate('alice', 'password')

A test client certificate, self-signed, for a client at 192.0.2.20 (import
``client.pem`` into ISE's Trusted Certificates):

.. code-block:: console

   $ openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout client.key -out client.pem \
       -subj "/CN=tacacs-client" -addext "extendedKeyUsage=clientAuth" \
       -addext "keyUsage=digitalSignature" -addext "basicConstraints=critical,CA:FALSE" \
       -addext "subjectAltName=IP:192.0.2.20"

ISE also accepts TLS 1.2 on the TLS port, and it can't be turned off; this
client always uses TLS 1.3.
