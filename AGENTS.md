# AGENTS.md

Guidance for coding agents working on this TACACS+ client library (RFC 8907). Read
`README.md` first for what it does and how to use it.

This is a maintained fork of the archived `ansible/tacacs_plus`. Its main user is
`durd/ise-cpp`, a web app where Cisco ISE users change their own password, which signs
in and changes passwords with this library.

## Rules

- Work on a feature branch and open a PR against `main`; never commit to `main`
  directly. CI (pytest on Python 3.10-3.15, ruff, wheel build) must pass before merging.
- The library never reads from the terminal or prints. Answers it doesn't have come from
  the caller's `prompt(server_msg, echo)` callback, or the session is aborted. Only the
  CLI (`bin/tacacs_client`) uses `getpass`/`input`.
- Never log secrets: passwords, the shared secret, PAP data or CHAP responses. The
  packet classes' `__str__` goes into the debug log, so mask anything secret there
  (see `TACACSAuthenticationContinue` and `TACACSAuthenticationStart._data_for_log`)
  and check new log lines.
- Logging calls pass their arguments (`logger.debug('sent <%s>', body)`), never
  f-strings or `%`/`.format()`; ruff's `G` rules check this. Everywhere else, use f-strings.
- Every session (one TCP connection) starts with `_new_session()`: a new session_id from
  `secrets` and the minor version reset. Reusing a session_id with the same secret repeats
  the obfuscation pad (RFC 8907 section 4.5), so don't cache session state on the client
  or use `random` for it.
- Don't change what goes on the wire by default (Latin-1 encoding, minor versions,
  prompt matching) without a version bump and a note in the PR: ise-cpp depends on it.
- Keep `bin/tacacs_client` and the root `tacacs_client` identical
  (`cp bin/tacacs_client tacacs_client`).
- Add a test for every behavior change. Protocol behavior is tested against
  `tests/tacacs_server.py` over TCP (`tests/test_rfc_server.py`); packet details and the
  dialog logic with a scripted socket (`tests/test_authen_dialog.py`).
- Don't run tests or the CLI against a production ISE or TACACS+ server: the change
  password calls change real passwords.
- No runtime dependencies (standard library only) and Python 3.10+. Keep it that way;
  the production server installs the wheel without internet.
- Versioning is semantic, in `setup.py`. A change in behavior that callers can notice
  (e.g. the library no longer prompting) is a major version.

## Gotchas

- **PyPI's `tacacs_plus` is the archived upstream 2.6**, not this code. ise-cpp
  installs this package as a wheel from an internal index; CI builds the wheel
  (`pip wheel --no-deps .`).
- **The test server is not ISE.** Its prompts ("Password: ", "Enter new password: ",
  "Confirm new password: ") are the same guesses the client makes, so passing tests
  show the client speaks the protocol, not that it works with ISE. How prompts are
  recognized is in `TACACSClient._prompt_kind` (regexes at the top of `client.py`) and
  `ANSWER_LIMITS`.
- **After an abort the server sends nothing.** The client sends CONTINUE with
  `TAC_PLUS_CONTINUE_FLAG_ABORT` via `send(..., expect_reply=False)` and returns at once,
  so a test can't assert on the test server's state right after an abort: the server
  thread may not have read it yet.
- **Flag `0x01` means two things:** `TAC_PLUS_REPLY_FLAG_NOECHO` in a server REPLY,
  `TAC_PLUS_CONTINUE_FLAG_ABORT` in a client CONTINUE. Test reply flags with
  `reply.noecho` (a bit test), never `== 0x01` or the abort constant.
- **`async_client.py` is behind `client.py`:** it answers only one GETPASS and has no
  `new_password`, `change_password`, `prompt` or `encoding`. ise-cpp doesn't use it.
  Fix bugs in both clients.
- **A `session_id` passed to `TACACSClient()` is used for every session.** It exists for
  tests; don't pass one in real code.
- **Errors:** `TimeoutError` when no reply comes in time, `TACACSProtocolError` (a
  subclass of `OSError`) for a reply that isn't TACACS+ or a connection closed mid-packet,
  other `OSError`s from the socket, `ValueError` for bad arguments.
- **ruff reads `ruff.toml`**, not `setup.cfg`. Files without `.py` are only linted when
  named: `ruff check . bin/tacacs_client tacacs_client`.
- **Tests:** `pip install -e . pytest pytest-cov pytest-asyncio ruff`, then `pytest` from
  the repo root. `setup.cfg` adds coverage options, so pytest needs `pytest-cov`.
  `tests/` is excluded from the wheel.

## Known issues

Not yet fixed; don't assume otherwise.

- Unverified against ISE 3.4p7: its prompt texts and order, whether it supports CHPASS,
  and whether it expects UTF-8 or Latin-1. A probe (`tools/tacacs_probe.py` on ise-cpp's
  `tools/tacacs-probe` branch) still has to be run.
- No release yet: no git tags, and wheels only exist as CI artifacts (kept 90 days).
- Obfuscation is MD5-based (RFC 8907 says to use TACACS+ only on secure networks);
  TACACS+ over TLS (RFC 9887) isn't supported.
- `async_client.flow_control()` connects with a blocking `socket.connect()` inside the
  event loop.
- `authorize()` and `account()` take `arguments=[]` as a default (not mutated, but
  fragile).
- `tacacs_client` exists twice (root and `bin/`).
