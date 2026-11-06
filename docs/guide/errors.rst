:hide-toc:

Errors and timeouts
===================

A wrong password is not an error: it's a reply with ``reply.invalid``.  Errors
are exceptions for when there is no usable reply:

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Exception
     - When
   * - ``TimeoutError``
     - No connection or no reply within ``timeout`` seconds (default 10).
   * - :class:`~tacacs_plus.exceptions.TACACSProtocolError`
     - The reply isn't TACACS+ (e.g. the wrong port), or it's garbled, or the
       server closed the connection mid-reply.  A **wrong shared secret** ends
       up here too: either the server hangs up (Cisco ISE does) or its reply
       can't be read, and the message then says "wrong shared secret?".
   * - ``ssl.SSLError``
     - With TLS: certificate not trusted, wrong name, handshake failed.
   * - ``OSError``
     - Anything else from the network, e.g. connection refused.
   * - ``ValueError``
     - Bad arguments, e.g. PAP without a password.

All but ``ValueError`` are ``OSError`` subclasses, so one ``except OSError``
covers "the server isn't usable right now".

.. code-block:: python
   :caption: handling all of them

   from tacacs_plus.client import TACACSClient
   from tacacs_plus.exceptions import TACACSProtocolError

   cli = TACACSClient('tacacs.example.com', 49, 'shared-secret', timeout=5)
   try:
       reply = cli.authenticate('alice', 'password')
   except TimeoutError:
       print('the server did not answer in time')
   except TACACSProtocolError as e:
       print('not a TACACS+ reply, check the port and secret:', e)
   except OSError as e:
       print('network problem:', e)
   else:
       print(reply.human_status)
