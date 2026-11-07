About
=====

What this library is, what it was built and tested against, and what it
doesn't do (yet).  If you rely on something listed as untested, test it against
your own server first, and please report what you find.

The project
-----------

``tacacs_plus`` is a TACACS+ client for Python.  It started as
`ansible/tacacs_plus <https://github.com/ansible/tacacs_plus>`_ by Ryan Petrello
(Ansible by Red Hat), which is now archived; this maintained version lives at
https://github.com/durd/tacacs_plus.  It is BSD licensed, like the original.

Version 3 was written for a web application where Cisco ISE users change their
own password.  That's why it has a non-interactive login dialog, password
changes over TACACS+, and TLS.  Releases are on
`GitHub <https://github.com/durd/tacacs_plus/releases>`_, not on PyPI: the
``tacacs_plus`` package on PyPI is the archived upstream 2.6.

Standards
---------

- `RFC 8907 <https://www.rfc-editor.org/rfc/rfc8907>`_, The TACACS+ Protocol:
  authentication (ASCII, PAP, CHAP, password change), authorization and
  accounting.
- `RFC 9887 <https://www.rfc-editor.org/rfc/rfc9887>`_, TACACS+ over TLS 1.3.

Requirements
------------

- Python 3.10 or newer; tested on 3.10 to 3.15.
- No other packages.  The wheel installs without internet access.
- TLS needs Python's ``ssl`` module with TLS 1.3, which every current Python build
  has.

How it's tested
---------------

Every change runs the test suite on Python 3.10 to 3.15 on Linux (GitHub
Actions), along with a lint check, a wheel build and a strict docs build.  The
tests are:

- **Unit tests** of the packet formats, the login dialog and reply parsing, with
  hand-built packets.
- **End-to-end tests over TCP** against a small TACACS+ server in the test suite
  (``tests/tacacs_server.py``), written from RFC 8907 rather than from the
  client code.  It handles ASCII, PAP and CHAP logins, an expired password,
  password change, authorization and accounting, with the obfuscation or with TLS.
  Both the socket and the asyncio client, and the command-line client, are run
  against it.
- **TLS tests** against that server, with a test CA and server and client
  certificates made for each run: TLS 1.3, client certificates, an unknown CA, a
  wrong server name, a server that only offers TLS 1.2, and an obfuscated reply.
- **Cisco ISE 3.4 (patch 7):**

  - without TLS, with ise-cpp's probe (a separate implementation of the same
    protocol): CHAP and ASCII logins, an expired password changed in the login
    dialog, and a voluntary password change (CHPASS).  ISE compares passwords as
    UTF-8 (pass ``encoding='utf-8'``), and a new password its policy refuses
    comes back as ``FAIL`` with ``server_msg`` "Password complexity does not
    meet".  Its prompts, which this client recognises (replayed in
    ``tests/test_authen_dialog.py``):

    - login: ``Password:``, and for an expired password then
      ``Enter New Password:`` and ``Enter New Password Confirmation:``;
    - CHPASS: ``Enter Old Password:``, ``Enter New Password:``,
      ``Enter New Password Confirmation:``.

  - with TLS 1.3 and a client certificate: an ASCII login with this library's
    command-line client (see :ref:`tls-ise`).
- Every example in this documentation has been run against the test server.

Development is done on macOS.

What isn't tested
-----------------

- **This library's password change against ISE.**  ISE's password-change
  dialogs were tried with ise-cpp's probe, not with ``change_password()`` or
  ``new_password``, and not over TLS.

- **Other servers.**  Version 2 was used with the free
  `tac_plus <http://www.shrubbery.net/tac_plus/>`_ server; version 3 hasn't been
  tested against tac_plus or any other server.
- **Authorization and accounting** are only tested against the test server,
  which answers fixed AV pairs.  Which AV pairs a real server expects and returns
  depends on its configuration.
- **Windows.**  Tests only run on Linux, and development is on macOS.
- **IPv6.**  The client can use IPv6 (``family=socket.AF_INET6``), but no test
  connects over it.

Limitations
-----------

- **Without TLS, the protection is weak.**  RFC 8907's obfuscation is based on
  MD5 and the shared secret; the RFC says to use it only on secure networks.  An
  ASCII or PAP login, or a password change, sends the passwords protected only
  by it.  CHAP doesn't send the password itself.  Use TLS where the server
  supports it.
- **TLS:** certificates only, no pre-shared keys.  Certificate revocation is
  checked only if you load CRLs into the context yourself, and OCSP isn't
  supported (see :func:`~tacacs_plus.tls.tls_context`).
- **Prompts are recognised by their text** in English: "new", "confirm",
  "re-enter" mean the new password; "old", "current" the current one; otherwise
  the order decides.  A server with other wording or another language may need
  changes in :mod:`tacacs_plus.authen_dialog`.
- **Passwords are sent as Latin-1** unless you pass ``encoding``; it must match
  what the server expects (Cisco ISE: ``'utf-8'``).
- **One session per connection.**  Each call opens a new TCP (or TLS) connection,
  runs one session and closes it.  RFC 8907's single-connection mode
  (``TAC_PLUS_SINGLE_CONNECT_FLAG``) would let later sessions reuse the
  connection, saving a connection (and with TLS, a handshake) per call.  It
  matters for clients that send many requests, such as a network device sending
  an accounting record for every command; for a few logins a minute it makes no
  noticeable difference.  It isn't implemented: the client would have to keep
  connections open between calls, reconnect when the server drops an idle one,
  and share them safely between threads.
- **FOLLOW and RESTART replies** aren't acted on: the client doesn't retry or
  connect elsewhere.  As RFC 8907 says, they count as a failed login, so
  ``reply.invalid`` is true for both (``reply.restart`` and ``reply.follow``
  tell them apart from FAIL):

  - *RESTART* means the server doesn't accept the login method the client used
    (e.g. PAP) and the client may start over with another ``authen_type``.  The
    RFC doesn't say how the server tells which methods it does accept, and a
    client that doesn't retry must treat RESTART as a failure.
  - *FOLLOW* means "ask another server instead".  RFC 8907 deprecates it as
    insecure: it must not be used in modern deployments, and clients should
    treat it as a failure.  The client never connects to another server.
- **Authentication is always for the "login" service**, and authorization and
  accounting always say the user was authenticated by TACACS+.  Other services
  (such as PPP or enable) and the RFC's ``SENDAUTH`` action aren't supported.

Reporting problems
------------------

Open an issue at https://github.com/durd/tacacs_plus/issues.  For a problem with
a server, say which server and version, and include the reply's
``human_status`` and ``server_msg``.  :doc:`guide/debugging` shows how to log
every packet; passwords are masked in that log, but usernames and server
messages aren't, so check before posting it.
