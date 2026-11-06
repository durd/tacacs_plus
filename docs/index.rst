tacacs_plus
===========

A TACACS+ client (`RFC 8907 <https://www.rfc-editor.org/rfc/rfc8907>`_) for
authentication, authorization and accounting, with a non-interactive ASCII
login and password change, and TACACS+ over TLS
(`RFC 9887 <https://www.rfc-editor.org/rfc/rfc9887>`_).

Start with :doc:`guide/start`; every page has examples you can copy.  The API
reference is built from the docstrings.

.. code-block:: python

   from tacacs_plus.client import TACACSClient

   cli = TACACSClient('tacacs.example.com', 49, 'shared-secret')
   reply = cli.authenticate('username', 'password')
   if reply.aborted and reply.getdata:
       # e.g. an expired password: ask the user for a new one, then
       reply = cli.authenticate('username', 'password', new_password='new')
   print(reply.human_status, reply.server_msg)

.. toctree::
   :caption: Project
   :maxdepth: 1

   about

.. toctree::
   :caption: Guide
   :maxdepth: 1

   guide/start
   guide/passwords
   guide/errors
   guide/authorization
   guide/tls
   guide/web-app
   guide/debugging

.. toctree::
   :caption: API reference
   :maxdepth: 1

   api/clients
   api/replies
   api/tls
   api/internals
