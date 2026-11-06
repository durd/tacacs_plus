tacacs_plus
===========

A TACACS+ client (`RFC 8907 <https://www.rfc-editor.org/rfc/rfc8907>`_) for
authentication, authorization and accounting, with a non-interactive ASCII
login and password change, and TACACS+ over TLS
(`RFC 9887 <https://www.rfc-editor.org/rfc/rfc9887>`_).

Installation, examples and the command-line client are described in the
`README <https://github.com/durd/tacacs_plus#readme>`_.  This is the API
reference, built from the docstrings.

.. code-block:: python

   from tacacs_plus.client import TACACSClient

   cli = TACACSClient('tacacs.example.com', 49, 'shared-secret')
   reply = cli.authenticate('username', 'password')
   if reply.aborted and reply.getdata:
       # e.g. an expired password: ask the user for a new one, then
       reply = cli.authenticate('username', 'password', new_password='new')
   print(reply.human_status, reply.server_msg)

.. toctree::
   :maxdepth: 2

   api
