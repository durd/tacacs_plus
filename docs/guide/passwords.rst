Passwords
=========

Signing in when a password has expired, changing passwords, PAP and CHAP,
non-ASCII passwords, and asking the user for answers.

.. _expired-password:

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

.. _pap-chap:

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
