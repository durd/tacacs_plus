# TACACS+ Python client

A maintained fork of [ansible/tacacs_plus](https://github.com/ansible/tacacs_plus),
which is archived.  Version 3.0.0 adds a non-interactive ASCII login and
password change (see below); the library no longer reads from the terminal.

A TACACS+ client that supports authentication, authorization and
accounting.

Unlike RADIUS, which was designed for similar purposes, the TACACS+ protocol
offers basic packet encryption but, as with most crypto designed back then,
it's [not secure](http://www.openwall.com/articles/TACACS+-Protocol-Security)
and definitely should not be used over untrusted networks.

This package has been successfully used with the free
[tac_plus](http://www.shrubbery.net/tac_plus/) TACACS+ server on a variety of
operating systems.

### Basic Installation and Usage

This fork isn't on PyPI, where `tacacs_plus` is the archived upstream 2.6.
Install it from git, or download the wheel from a
[GitHub release](https://github.com/durd/tacacs_plus/releases) (or build one
with `pip wheel --no-deps .`) and upload it to your own index.

```
$ pip install git+https://github.com/durd/tacacs_plus.git

$ tacacs_client -u myuser -H localhost authenticate
$ tacacs_client -u myuser -H localhost -v change-password
$ tacacs_client -u myuser -H localhost authenticate -t pap
$ tacacs_client -u myuser -H localhost -v authenticate -t chap
status: PASS

$ tacacs_client -u myuser -H localhost authorize -c service=shell cmd=show cmdarg=version
$ tacacs_client -u myuser -H localhost -v authorize -t pap -c service=shell cmd=show cmdarg=version
status: PASS

$ tacacs_client -u myuser -H localhost -v authorize -t pap -c service=junos-exec
status: REPL
av-pairs:
    allow-commands=^acommandregex$
    deny-commands=^anothercommandregex$

$ tacacs_client -u myuser -H localhost account -f start -c service=shell cmd=show cmdarg=version
$ tacacs_client -u myuser -H localhost account -f stop -c service=shell cmd=show cmdarg=version

$ tacacs_client -h
usage: tacacs_client [-h] -u USERNAME -H HOST [-p PORT] [-l PRIV_LVL]
                     [-t {ascii,pap,chap}] [-r REM_ADDR] [-P VIRTUAL_PORT]
                     [--timeout TIMEOUT] [-d] [-v] [-6] [-k KEY]
                     {authenticate,change-password,authorize,account} ...

        Tacacs+ client with full AAA support:

            * Authentication supports ascii, pap and chap
            * Authorization supports AV pairs and single commands.
            * Accounting support AV pairs and single commands.

        NOTE: shared encryption key can be set via environment variable TACACS_PLUS_KEY or via argument.
        NOTE: user password can be setup via environment variable TACACS_PLUS_PWD or via argument.


positional arguments:
  {authenticate,change-password,authorize,account}
                        action to perform over the tacacs+ server
    authenticate        authenticate against a tacacs+ server
    change-password     change a user's password (asks for the new password)
    authorize           authorize a command against a tacacs+ server
    account             account commands with accounting flags against a tacacs+ server

options:
  -h, --help            show this help message and exit
  -u, --username USERNAME
                        user name
  -H, --host HOST       tacacs+ server address
  -p, --port PORT       tacacs+ server port (default 49)
  -l, --priv-lvl PRIV_LVL
                        user privilege level
  -t, --authen-type {ascii,pap,chap}
                        authentication type
  -r, --rem-addr REM_ADDR
                        remote address (logged by tacacs server)
  -P, --virtual-port VIRTUAL_PORT
                        console port used in connection (logged by tacacs server)
  --timeout TIMEOUT
  -d, --debug           enable debugging output
  -v, --verbose         print responses
  -6, --v6              use IPv6 addresses
  -k, --key KEY         tacacs+ shared encryption key

$ tacacs_client authenticate -h
usage: tacacs_client authenticate [-h] [-p PASSWORD]

options:
  -h, --help            show this help message and exit
  -p, --password PASSWORD
                        user password

$ tacacs_client change-password -h
usage: tacacs_client change-password [-h] [-p PASSWORD]

options:
  -h, --help            show this help message and exit
  -p, --password PASSWORD
                        current user password

$ tacacs_client authorize -h
usage: tacacs_client authorize [-h] -c CMDS [CMDS ...]

options:
  -h, --help            show this help message and exit
  -c, --cmds CMDS [CMDS ...]
                        list of cmds to authorize

$ tacacs_client account -h
usage: tacacs_client account [-h] -c CMDS [CMDS ...]
                                                 -f {start,stop,update}

options:
  -h, --help            show this help message and exit
  -c, --cmds CMDS [CMDS ...]
                        list of cmds to authorize
  -f, --flag {start,stop,update}
                        accounting flag
```

### Programmatic Usage

```python
#!/usr/bin/env python
from __future__ import print_function

from tacacs_plus.client import TACACSClient
from tacacs_plus.flags import TAC_PLUS_ACCT_FLAG_START, TAC_PLUS_ACCT_FLAG_WATCHDOG, TAC_PLUS_ACCT_FLAG_STOP
import socket

# For IPv6, use `family=socket.AF_INET6`
cli = TACACSClient('host', 49, 'secret', timeout=10, family=socket.AF_INET)

# authenticate user and pass
authen = cli.authenticate('username', 'password')
print("PASS!" if authen.valid else "FAIL!")

# authorize user and command
author = cli.authorize('username', arguments=[b"service=shell", b"cmd=show", b"cmdargs=version"])
print("PASS!" if author.valid else "FAIL!")

# start accounting session for command
acct = cli.account('username', TAC_PLUS_ACCT_FLAG_START, arguments=[b"service=shell", b"cmd=show", b"cmdargs=version"])
print("PASS!" if acct.valid else "FAIL!")

# continue accounting session for another command
acct = cli.account('username', TAC_PLUS_ACCT_FLAG_WATCHDOG, arguments=[b"service=shell", b"cmd=debug", b"cmdargs=aaa"])
print("PASS!" if acct.valid else "FAIL!")

# close accounting session
acct = cli.account('username', TAC_PLUS_ACCT_FLAG_STOP, arguments=[b"service=shell", b"cmd=exit"])
print("PASS!" if acct.valid else "FAIL!")
```

#### Non-interactive ASCII login and password change

With ASCII authentication the server leads a dialog (GETUSER, GETPASS,
GETDATA).  The client answers it from the values it is given and never reads
from the terminal itself, so it can run inside a web application:

```python
from tacacs_plus.client import TACACSClient

cli = TACACSClient('host', 49, 'secret')

# a user whose password must be changed at login
authen = cli.authenticate('username', 'password', encoding='utf-8')
if authen.getdata and authen.aborted:
    # the server asked for something we had no answer for, e.g. a new
    # password; the session was aborted, authen.server_msg has the prompt
    authen = cli.authenticate('username', 'password', new_password='new',
                              encoding='utf-8')

# change a password (action CHPASS)
authen = cli.change_password('username', 'old', 'new', encoding='utf-8')
print(authen.human_status, authen.server_msg)
```

Password prompts are matched by their text ("new", "confirm", "old", ...)
and otherwise by order: the first one gets the password, later ones the new
password.  The dialog is aborted after `max_steps` (default 10) answers, or
when the server asks for the same thing too often (e.g. it rejects the new
password).  `encoding` (default `latin-1`, as before) is used for the
username and passwords.  Pass `prompt=callable(server_msg, echo)` to ask a
user for answers the client doesn't have; `tacacs_client` does that.


### Development

```
$ pip install -e . pytest pytest-cov pytest-asyncio ruff
$ pytest
$ ruff check . bin/tacacs_client tacacs_client
```

`tests/tacacs_server.py` is a small TACACS+ server written from RFC 8907 (PAP,
CHAP, the ASCII login dialog and change password, an expired-password user).
`tests/test_rfc_server.py` runs the client against it over TCP.  It shows that
the client speaks the protocol, not how a particular server such as Cisco ISE
behaves: its prompts are guesses.  You can also start it by hand to try
`tacacs_client`:

```
$ python -c "import time; from tests.tacacs_server import TacacsServer; \
    s = TacacsServer('key', {'alice': 'secret'}); print(s.port); time.sleep(3600)"
```
