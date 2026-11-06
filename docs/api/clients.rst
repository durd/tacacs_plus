Clients
=======

Both clients have the same methods and arguments; the asyncio one's are
coroutines.  Examples: :doc:`../guide/start`.

Socket client
-------------

.. autoclass:: tacacs_plus.client.TACACSClient
   :members: authenticate, change_password, authorize, account, send

Asyncio client
--------------

.. autoclass:: tacacs_plus.async_client.TACACSClient
   :members: authenticate, change_password, authorize, account, send
   :no-index:
