Replies and errors
==================

What the clients return and raise.  How to use them:
:ref:`reading-the-reply` and :doc:`../guide/errors`.

Authentication
--------------

.. autoclass:: tacacs_plus.authentication.TACACSAuthenticationReply
   :members: valid, invalid, error, getuser, getpass, getdata, noecho, human_status

Authorization
-------------

.. autoclass:: tacacs_plus.authorization.TACACSAuthorizationReply
   :members:

Accounting
----------

.. autoclass:: tacacs_plus.accounting.TACACSAccountingReply
   :members:

Errors
------

.. automodule:: tacacs_plus.exceptions
