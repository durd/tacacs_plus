API reference
=============

Clients
-------

Both clients have the same methods and arguments; the asyncio one's are
coroutines.

.. autoclass:: tacacs_plus.client.TACACSClient
   :members: authenticate, change_password, authorize, account, send

.. autoclass:: tacacs_plus.async_client.TACACSClient
   :members: authenticate, change_password, authorize, account, send
   :no-index:

TLS
---

.. automodule:: tacacs_plus.tls

Errors
------

.. automodule:: tacacs_plus.exceptions

Replies
-------

.. autoclass:: tacacs_plus.authentication.TACACSAuthenticationReply
   :members: valid, invalid, error, getuser, getpass, getdata, noecho, human_status

.. autoclass:: tacacs_plus.authorization.TACACSAuthorizationReply
   :members:

.. autoclass:: tacacs_plus.accounting.TACACSAccountingReply
   :members:

The ASCII dialog
----------------

How the clients answer the server's prompts.

.. automodule:: tacacs_plus.authen_dialog
   :members: prompt_kind, AuthenDialog, ANSWER_LIMITS

Constants
---------

.. automodule:: tacacs_plus.flags
   :members:
   :undoc-members:

Packets
-------

.. automodule:: tacacs_plus.packet
   :members: to_bytes, crypt, TACACSPacket, TACACSHeader
