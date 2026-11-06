:hide-toc:

Internals
=========

Not needed for everyday use, but useful to understand what the clients do.

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
   :members: to_bytes, check_reply, crypt, TACACSPacket, TACACSHeader
