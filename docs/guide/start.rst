Getting started
===============

Most examples have a **Sync** tab for the socket client (``tacacs_plus.client``)
and an **Async** tab for the asyncio client (``tacacs_plus.async_client``);
picking one switches them all.

Every example is complete enough to copy; replace the host, secret, users and
passwords with your own.

Before you start
----------------

Install the package (it has no dependencies)::

   $ pip install git+https://github.com/durd/tacacs_plus.git

You need three things from whoever runs the TACACS+ server:

- the server's **host** name or IP address and **port** (usually 49);
- the **shared secret** configured for your machine on the server (with TLS,
  the CA certificate instead, see :doc:`tls`);
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

This is an ASCII login, the default.  For PAP and CHAP, see :ref:`pap-chap`.

.. _reading-the-reply:

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
       :ref:`expired-password`.
   * - ``reply.server_msg``
     - The server's message as **bytes**, e.g. why a new password was refused.
       Decode it before showing it: ``reply.server_msg.decode('utf-8', 'replace')``.
   * - ``reply.human_status == 'RESTART'``
     - The server doesn't accept this login method, e.g. PAP.  Try again with
       another ``authen_type``, or treat it as a failed login.  Rare.
   * - ``reply.human_status == 'FOLLOW'``
     - "Ask another server".  Deprecated as insecure by RFC 8907: treat it as a
       failed login.  Rare.
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
