:hide-toc:

Authorization and accounting
============================

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
