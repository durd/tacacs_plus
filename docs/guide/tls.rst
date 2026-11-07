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
