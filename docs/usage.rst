Usage
=====

Each example has a tab for the socket client (``tacacs_plus.client``) and the
asyncio client (``tacacs_plus.async_client``); picking one switches them all.

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
         print(reply.valid, reply.human_status)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         from tacacs_plus.async_client import TACACSClient

         cli = TACACSClient('tacacs.example.com', 49, 'shared-secret')
         reply = await cli.authenticate('alice', 'password')
         print(reply.valid, reply.human_status)

The default is an ASCII login; pass ``authen_type=TAC_PLUS_AUTHEN_TYPE_PAP`` or
``TAC_PLUS_AUTHEN_TYPE_CHAP`` (with ``chap_ppp_id`` and ``chap_challenge``) from
:mod:`tacacs_plus.flags` for PAP or CHAP.

Expired password
----------------

When the server asks for something the client has no answer for, such as a new
password, the client aborts the session and returns the server's question with
``reply.aborted`` set.  Ask the user, then sign in again with ``new_password``:

.. tab-set::
   :sync-group: client

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         reply = cli.authenticate('alice', 'password')
         if reply.aborted and reply.getdata:
             print(reply.server_msg.decode())   # e.g. "Enter new password: "
             reply = cli.authenticate('alice', 'password', new_password='N3w-password')

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         reply = await cli.authenticate('alice', 'password')
         if reply.aborted and reply.getdata:
             print(reply.server_msg.decode())   # e.g. "Enter new password: "
             reply = await cli.authenticate('alice', 'password', new_password='N3w-password')

Change a password
-----------------

.. tab-set::
   :sync-group: client

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         reply = cli.change_password('alice', 'old-password', 'N3w-password')
         if not reply.valid:
             print(reply.server_msg.decode())   # the server's reason, e.g. its password policy

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         reply = await cli.change_password('alice', 'old-password', 'N3w-password')
         if not reply.valid:
             print(reply.server_msg.decode())   # the server's reason, e.g. its password policy

Ask the user interactively
--------------------------

Pass ``prompt`` to answer questions the client has no answer for, instead of
aborting.  It gets the server's message and whether the answer may be shown.
For the asyncio client it may also be a coroutine function.

.. tab-set::
   :sync-group: client

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

         import getpass

         def ask(server_msg, echo):
             return input(server_msg) if echo else getpass.getpass(server_msg)

         reply = cli.authenticate('alice', 'password', prompt=ask)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

         async def ask(server_msg, echo):
             # my_web_form stands for however your app asks the user
             return await my_web_form(server_msg, hidden=not echo)

         reply = await cli.authenticate('alice', 'password', prompt=ask)

TACACS+ over TLS
----------------

With TLS (RFC 9887) there is no shared secret: the connection is encrypted and
the server is checked against its certificate.  See :mod:`tacacs_plus.tls`.

.. tab-set::

   .. tab-item:: Without TLS

      .. code-block:: python

         cli = TACACSClient('tacacs.example.com', 49, 'shared-secret')

   .. tab-item:: With TLS

      .. code-block:: python

         from tacacs_plus.tls import tls_context

         tls = tls_context(cafile='tacacs-ca.pem')
         cli = TACACSClient('tacacs.example.com', 300, None, tls=tls)

   .. tab-item:: With a client certificate

      .. code-block:: python

         from tacacs_plus.tls import tls_context

         tls = tls_context(cafile='tacacs-ca.pem',
                           certfile='client.pem', keyfile='client.key')
         cli = TACACSClient('tacacs.example.com', 300, None, tls=tls)

Command line
------------

.. code-block:: console

   $ tacacs_client -H tacacs.example.com -u alice -v authenticate
   $ tacacs_client -H tacacs.example.com -u alice -v change-password
   $ tacacs_client -H tacacs.example.com -p 300 --tls-ca tacacs-ca.pem -u alice -v authenticate
