:hide-toc:

Debugging and the command line
==============================

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
