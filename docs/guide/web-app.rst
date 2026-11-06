Example: a web application
==========================

A complete sign-in function for a web app, with the expired-password case.  The
form posts the username and password, and on the second step also the new
password twice; the password is never kept between requests.

.. code-block:: python

   from tacacs_plus.client import TACACSClient

   cli = TACACSClient('tacacs.example.com', 49, 'shared-secret', timeout=10)

   def sign_in(username, password, new_password=None):
       """Returns ('ok', None), ('new-password', prompt), ('wrong', None) or ('error', message)."""
       try:
           reply = cli.authenticate(username, password, new_password=new_password)
       except OSError:
           return 'error', 'Sign-in is unavailable right now.'
       message = reply.server_msg.decode('utf-8', 'replace')
       if reply.valid:
           return 'ok', None
       if reply.aborted and reply.getdata:
           return 'new-password', message      # show a form: current, new, repeat
       if reply.invalid:
           return 'wrong', None
       return 'error', message or 'Sign-in failed.'

   # first request: the user submits username and password
   state, info = sign_in('alice', 'old-password')
   # -> ('new-password', 'Enter new password: ') for an expired password

   # second request: the form with current password, new password and its repeat
   state, info = sign_in('alice', 'old-password', new_password='N3w-password')
   # -> ('ok', None)
