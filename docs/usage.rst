Usage
=====

Examples for everything the library does.  Most have a tab for the socket
client (``tacacs_plus.client``) and the asyncio client
(``tacacs_plus.async_client``); picking one switches them all.  Every example is
complete enough to copy; replace the host, secret, users and passwords with
your own.

.. contents:: On this page
   :local:
   :depth: 1

Before you start
----------------

Install the package (it has no dependencies)::

   $ pip install git+https://github.com/durd/tacacs_plus.git

You need three things from whoever runs the TACACS+ server:

- the server's **host** name or IP address and **port** (usually 49);
- the **shared secret** configured for your machine on the server (with TLS,
  the CA certificate instead, see `TACACS+ over TLS`_);
- a **test user** to try things with.

Every call opens a new connection, runs one *session* and closes it again, so a
client object can be reused and kept around.

Sign in
-------

.. tab-set::
   :sync-group: client

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         from tacacs_plus.client import TACACSClient

         cli = TACACSClient('tacacs.example.com', 49, 'shared-secret')
         reply = cli.authenticate('alice', 'password')
         if reply.valid:
             print('signed in')
         else:
             print('not signed in:', reply.human_status)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         import asyncio
         from tacacs_plus.async_client import TACACSClient

         async def main():
             cli = TACACSClient('tacacs.example.com', 49, 'shared-secret')
             reply = await cli.authenticate('alice', 'password')
             if reply.valid:
                 print('signed in')
             else:
                 print('not signed in:', reply.human_status)

         asyncio.run(main())

This is an ASCII login, the default.  For PAP and CHAP, see `PAP and CHAP`_.

Reading the reply
-----------------

``authenticate()`` and ``change_password()`` return a
:class:`~tacacs_plus.authentication.TACACSAuthenticationReply`.  What it can
mean, and what to do:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Reply
     - Meaning
   * - ``reply.valid``
     - Accepted (status ``PASS``).
   * - ``reply.invalid``
     - Wrong username or password (``FAIL``).
   * - ``reply.error``
     - The server couldn't handle the request (``ERROR``).  Cisco ISE answers
       this for CHAP when the password must be changed.
   * - ``reply.aborted`` and ``reply.getdata``
     - The server asked something the client had no answer for, usually a new
       password; ``reply.server_msg`` holds the question.  See
       `Expired password`_.
   * - ``reply.server_msg``
     - The server's message as **bytes**, e.g. why a new password was refused.
       Decode it before showing it: ``reply.server_msg.decode('utf-8', 'replace')``.
   * - ``reply.human_status``
     - The status as text (``'PASS'``, ``'FAIL'``, ...), handy for logs.

.. code-block:: python

   reply = cli.authenticate('alice', 'password')
   message = reply.server_msg.decode('utf-8', 'replace')
   if reply.valid:
       print('signed in')
   elif reply.aborted and reply.getdata:
       print('the server wants more:', message)       # e.g. "Enter new password: "
   elif reply.invalid:
       print('wrong username or password')
   else:
       print('server error:', reply.human_status, message)

Expired password
----------------

When a password has expired (in Cisco ISE: "change password at next login"),
the server asks for a new one during the login.  Without an answer the client
aborts the session and returns that question.  Ask the user for a new password,
then sign in again with ``new_password``; the server checks the old one, sets
the new one and signs the user in.

.. tab-set::
   :sync-group: client

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         reply = cli.authenticate('alice', 'old-password')
         if reply.aborted and reply.getdata:
             print(reply.server_msg.decode())          # "Enter new password: "
             reply = cli.authenticate('alice', 'old-password',
                                      new_password='N3w-password')
         print(reply.human_status)                     # PASS: changed and signed in

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         reply = await cli.authenticate('alice', 'old-password')
         if reply.aborted and reply.getdata:
             print(reply.server_msg.decode())          # "Enter new password: "
             reply = await cli.authenticate('alice', 'old-password',
                                            new_password='N3w-password')
         print(reply.human_status)                     # PASS: changed and signed in

The client sends the new password for both "new password" and "confirm"
prompts.  If the server refuses it (for example its password policy), it asks
again; the client then aborts instead of sending the same password a third
time, and ``reply.server_msg`` usually says why.

Change a password
-----------------

A voluntary change, for a user whose password hasn't expired.  The server must
support it (action ``CHPASS``); if it doesn't, ``reply.error`` is set.

.. tab-set::
   :sync-group: client

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         reply = cli.change_password('alice', 'old-password', 'N3w-password')
         if reply.valid:
             print('password changed')
         else:
             print('not changed:', reply.server_msg.decode('utf-8', 'replace'))

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         reply = await cli.change_password('alice', 'old-password', 'N3w-password')
         if reply.valid:
             print('password changed')
         else:
             print('not changed:', reply.server_msg.decode('utf-8', 'replace'))

PAP and CHAP
------------

Some servers only allow these.  CHAP never sends the password itself, only a
hash of it with a challenge; use a new random ID and challenge every time.

.. tab-set::
   :sync-group: client

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         import secrets
         from tacacs_plus.flags import TAC_PLUS_AUTHEN_TYPE_CHAP, TAC_PLUS_AUTHEN_TYPE_PAP

         reply = cli.authenticate('alice', 'password', authen_type=TAC_PLUS_AUTHEN_TYPE_PAP)

         reply = cli.authenticate(
             'alice', 'password',
             authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP,
             chap_ppp_id=secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ'),  # 1 character
             chap_challenge=secrets.token_hex(16),                       # up to 255
         )

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         import secrets
         from tacacs_plus.flags import TAC_PLUS_AUTHEN_TYPE_CHAP, TAC_PLUS_AUTHEN_TYPE_PAP

         reply = await cli.authenticate('alice', 'password', authen_type=TAC_PLUS_AUTHEN_TYPE_PAP)

         reply = await cli.authenticate(
             'alice', 'password',
             authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP,
             chap_ppp_id=secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ'),  # 1 character
             chap_challenge=secrets.token_hex(16),                       # up to 255
         )

PAP and CHAP have no dialog, so ``new_password`` and ``prompt`` only work with
ASCII logins.

Passwords with å, ä, ö or €
---------------------------

Passwords are sent as Latin-1 by default, like tacacs_plus 2.x, which can't
encode ``€``.  The server must expect the same encoding as the client, so check
which one yours uses and pass it everywhere:

.. code-block:: python

   reply = cli.authenticate('alice', 'Sommar€2026', encoding='utf-8')
   reply = cli.change_password('alice', 'gammalt', 'Höst€2026', encoding='utf-8')

With the wrong encoding a correct non-ASCII password simply fails
(``reply.invalid``).

Ask the user interactively
--------------------------

Instead of aborting, the client can ask *you* for answers it doesn't have: pass
``prompt``.  It gets the server's message and whether the answer may be shown
(``echo``), and returns the answer, or ``None`` to abort.

.. tab-set::
   :sync-group: client

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         import getpass

         def ask(server_msg, echo):
             if echo:
                 return input(server_msg)
             return getpass.getpass(server_msg)      # hidden, for passwords

         reply = cli.authenticate('alice', 'password', prompt=ask)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         async def ask(server_msg, echo):
             # stands for however your app asks the user, e.g. a web form
             return await show_form(server_msg, hidden=not echo)

         reply = await cli.authenticate('alice', 'password', prompt=ask)

``prompt`` is also asked for a missing PAP or CHAP password.

Errors and timeouts
-------------------

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

A web application
-----------------

A complete sign-in function for a web app, with the expired-password case.  The
form posts the username and password, and on the second step also the new
password twice; the password is never kept between requests.

.. code-block:: python

   from tacacs_plus.client import TACACSClient

   cli = TACACSClient('tacacs.example.com', 49, 'shared-secret', timeout=10)

   def sign_in(username, password, new_password=None):
       """Returns ('ok', None), ('new-password', prompt), ('wrong', None) or ('error', message)."""
       try:
           reply = cli.authenticate(username, password, new_password=new_password)
       except OSError:
           return 'error', 'Sign-in is unavailable right now.'
       message = reply.server_msg.decode('utf-8', 'replace')
       if reply.valid:
           return 'ok', None
       if reply.aborted and reply.getdata:
           return 'new-password', message      # show a form: current, new, repeat
       if reply.invalid:
           return 'wrong', None
       return 'error', message or 'Sign-in failed.'

   # first request: the user submits username and password
   state, info = sign_in('alice', 'old-password')
   # -> ('new-password', 'Enter new password: ') for an expired password

   # second request: the form with current password, new password and its repeat
   state, info = sign_in('alice', 'old-password', new_password='N3w-password')
   # -> ('ok', None)

Authorization
-------------

Ask the server whether a user may do something.  Requests and answers are lists
of *AV pairs* (attribute=value) as **bytes**; which ones a server understands
depends on its configuration.

.. tab-set::
   :sync-group: client

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         reply = cli.authorize('alice', arguments=[b'service=shell', b'cmd='])
         if reply.valid:
             # the server's AV pairs, e.g. [b'priv-lvl=15', b'role=admin']
             attributes = dict(arg.decode().split('=', 1) for arg in reply.arguments)
             print(attributes.get('priv-lvl'), attributes.get('role'))
         else:
             print('not authorized:', reply.human_status)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         reply = await cli.authorize('alice', arguments=[b'service=shell', b'cmd='])
         if reply.valid:
             # the server's AV pairs, e.g. [b'priv-lvl=15', b'role=admin']
             attributes = dict(arg.decode().split('=', 1) for arg in reply.arguments)
             print(attributes.get('priv-lvl'), attributes.get('role'))
         else:
             print('not authorized:', reply.human_status)

To require a privilege level, pass ``priv_lvl``: if the server answers with a
lower ``priv-lvl``, the reply is turned into a failure.

.. code-block:: python

   reply = cli.authorize('alice', arguments=[b'service=shell'], priv_lvl=15)
   print(reply.valid)    # False if the server gave alice less than 15

Accounting
----------

Tell the server what a user did: a START record when something begins, a STOP
record when it ends, with the same ``task_id``.

.. tab-set::
   :sync-group: client

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         from tacacs_plus.flags import TAC_PLUS_ACCT_FLAG_START, TAC_PLUS_ACCT_FLAG_STOP

         args = [b'task_id=42', b'service=shell', b'cmd=show version']
         cli.account('alice', TAC_PLUS_ACCT_FLAG_START, arguments=args)
         # ... the command runs ...
         reply = cli.account('alice', TAC_PLUS_ACCT_FLAG_STOP, arguments=args)
         print(reply.valid)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         from tacacs_plus.flags import TAC_PLUS_ACCT_FLAG_START, TAC_PLUS_ACCT_FLAG_STOP

         args = [b'task_id=42', b'service=shell', b'cmd=show version']
         await cli.account('alice', TAC_PLUS_ACCT_FLAG_START, arguments=args)
         # ... the command runs ...
         reply = await cli.account('alice', TAC_PLUS_ACCT_FLAG_STOP, arguments=args)
         print(reply.valid)

``TAC_PLUS_ACCT_FLAG_WATCHDOG`` sends an update for something still running.

TACACS+ over TLS
----------------

With TLS (RFC 9887) the connection is encrypted and the server is checked
against its certificate; there is no shared secret (pass ``None``).  You need
the CA certificate that signed the server's certificate, as a PEM file.  RFC
9887 registers port 300 for it.

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
         cli = TACACSClient('tacacs.example.com', 300, None, tls=tls)

   .. tab-item:: With a client certificate

      .. code-block:: python

         from tacacs_plus.client import TACACSClient
         from tacacs_plus.tls import tls_context

         tls = tls_context(cafile='tacacs-ca.pem',
                           certfile='client.pem', keyfile='client.key')
         cli = TACACSClient('tacacs.example.com', 300, None, tls=tls)

   .. tab-item:: By IP address

      .. code-block:: python

         from tacacs_plus.client import TACACSClient
         from tacacs_plus.tls import tls_context

         # the certificate is for tacacs.example.com, not for the address
         tls = tls_context(cafile='tacacs-ca.pem')
         cli = TACACSClient('192.0.2.10', 300, None, tls=tls,
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

Debugging
---------

The library logs every packet at ``DEBUG`` level through the ``tacacs_plus``
loggers.  Passwords, PAP data and CHAP responses are masked, but usernames,
server messages and AV pairs are logged.

.. code-block:: python

   import logging

   logging.basicConfig(level=logging.WARNING)
   logging.getLogger('tacacs_plus').setLevel(logging.DEBUG)   # only this library

   reply = cli.authenticate('alice', 'password')
   # DEBUG:tacacs_plus.client:TACACSAuthenticationStart
   # sent header <version: 192, type: 1, session_id: ..., length: 36, seq_no: 1, flags: 0>
   # ...

Command line
------------

``tacacs_client`` is installed with the package.  It asks for the shared secret
and passwords when they aren't given (or set ``TACACS_PLUS_KEY`` and
``TACACS_PLUS_PWD``), and for every question the server asks.

.. code-block:: console

   $ tacacs_client -H tacacs.example.com -u alice -v authenticate
   $ tacacs_client -H tacacs.example.com -u alice -v authenticate -t chap
   $ tacacs_client -H tacacs.example.com -u alice -v change-password
   $ tacacs_client -H tacacs.example.com -u alice -v authorize -c service=shell cmd=
   $ tacacs_client -H tacacs.example.com -u alice account -f start -c task_id=1 service=shell
   $ tacacs_client -H tacacs.example.com -p 300 --tls-ca tacacs-ca.pem -u alice -v authenticate

``-v`` prints the reply; ``tacacs_client -h`` lists all options.
