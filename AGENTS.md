# AGENTS.md

Guidance for coding agents working on this TACACS+ client library (RFC 8907). Read
`README.md` first for what it does and how to use it.

This is a maintained fork of the archived `ansible/tacacs_plus`. Its main user is
`durd/ise-cpp`, a web app where Cisco ISE users change their own password, which signs
in and changes passwords with this library.

## Rules

- Work on a feature branch and open a PR against `main`; never commit to `main`
  directly. CI (pytest on Python 3.10-3.15, ruff, wheel build, docs build) must pass before merging;
  branch protection enforces both, for admins too. If you rename a CI job or change the
  Python matrix, update the required checks in the branch protection to match, or PRs
  can't be merged.
- The library never reads from the terminal or prints. Answers it doesn't have come from
  the caller's `prompt(server_msg, echo)` callback, or the session is aborted. Only the
  CLI (`bin/tacacs_client`) uses `getpass`/`input`.
- Never log secrets: passwords, the shared secret, PAP data or CHAP responses. The
  packet classes' `__str__` goes into the debug log, so mask anything secret there
  (see `TACACSAuthenticationContinue` and `TACACSAuthenticationStart._data_for_log`)
  and check new log lines.
- Docstrings are the API reference: `docs/api/*.rst` pull them in with Sphinx autodoc,
  and CI builds it with `-W`, so broken reST markup fails the PR. Use reST field lists
  (`:param x:`, `:return:`, `:raises:`), `::` before an indented code block, and
  document constructor arguments in `__init__` (`autoclass_content = 'both'`). A new
  public module or class needs an entry in `docs/api/`. Examples live in `docs/guide/`,
  one short page per topic, in Sync/Async tabs (sphinx-design `tab-set` with
  `:sync-group: client`) that should stay in step with each other. The left menu lists
  pages (the toctrees in `docs/index.rst`; add new pages there), Furo's right-hand menu
  lists the current page's sections. Don't add `.. contents::`: Furo shows it as an error.
- `docs/about.rst` and the README's "Status" section say what is tested, what isn't and
  the limitations. Keep both true: update them when something gets tested (e.g.
  against ISE) or a limitation is lifted.
- Logging calls pass their arguments (`logger.debug('sent <%s>', body)`), never
  f-strings or `%`/`.format()`; ruff's `G` rules check this. Everywhere else, use f-strings.
- Every session (one TCP connection) starts with `_new_session()`: a new session_id from
  `secrets` and the minor version reset. Reusing a session_id with the same secret repeats
  the obfuscation pad (RFC 8907 section 4.5), so don't cache session state on the client
  or use `random` for it.
- Don't change what goes on the wire by default (Latin-1 encoding, minor versions,
  prompt matching) without a version bump and a note in the PR: ise-cpp depends on it.
- Add a test for every behavior change. Protocol behavior is tested against
  `tests/tacacs_server.py` over TCP (`tests/test_rfc_server.py`); packet details and the
  dialog logic with a scripted socket (`tests/test_authen_dialog.py`).
- Don't run tests or the CLI against a production ISE or TACACS+ server: the change
  password calls change real passwords.
- Dev tools are pinned in `requirements-dev.txt` (CI, tox and the release use it), the
  docs tools in `docs/requirements.txt`; Dependabot updates them and the GitHub Actions
  versions weekly.
- No runtime dependencies (standard library only) and Python 3.10+. Keep it that way;
  the production server installs the wheel without internet.
- Versioning is semantic, in `setup.py`. A change in behavior that callers can notice
  (e.g. the library no longer prompting) is a major version. To release, bump the
  version in a PR, then push a tag `v<version>` on `main`;
  `.github/workflows/release.yml` checks the tag matches, runs the tests and publishes
  the wheel and sdist as a GitHub release; `.github/workflows/pages.yml` publishes the
  docs to https://durd.github.io/tacacs_plus/ for the same tag.

## Gotchas

- **PyPI's `tacacs_plus` is the archived upstream 2.6**, not this code. ise-cpp
  installs this package as a wheel from an internal index; CI builds the wheel
  (`pip wheel --no-deps .`).
- **The test server is not ISE.** Its prompts ("Password: ", "Enter new password: ",
  "Confirm new password: ") are the same guesses the client makes, so passing tests
  show the client speaks the protocol, not that it works with ISE. ISE's real prompts
  are replayed in `tests/test_authen_dialog.py` (`test_ise_*`); keep those passing when
  changing prompt matching. How prompts are
  recognized is in `tacacs_plus/authen_dialog.py` (`prompt_kind`, the regexes and
  `ANSWER_LIMITS`).
- **After an abort the server sends nothing.** The client sends CONTINUE with
  `TAC_PLUS_CONTINUE_FLAG_ABORT` via `send(..., expect_reply=False)` and returns at once,
  so a test can't assert on the test server's state right after an abort: the server
  thread may not have read it yet.
- **Flag `0x01` means two things:** `TAC_PLUS_REPLY_FLAG_NOECHO` in a server REPLY,
  `TAC_PLUS_CONTINUE_FLAG_ABORT` in a client CONTINUE. Test reply flags with
  `reply.noecho` (a bit test), never `== 0x01` or the abort constant.
- **Two clients, one API:** `client.py` (sockets) and `async_client.py` (asyncio) have
  the same methods and arguments. What they share (START data, prompt matching,
  answer limits) is in `authen_dialog.py`; each keeps its own send loop. Change and
  test both: `tests/test_rfc_server.py` runs the async client against the test server
  too. ise-cpp uses the sync one.
- **TLS (`tacacs_plus/tls.py`, RFC 9887):** with `tls`, `secret` must be None, packets
  carry `TAC_PLUS_UNENCRYPTED_FLAG` and aren't obfuscated, and a reply without the flag
  is a `TACACSProtocolError`. `port=None` means `default_port()`: 49, or 6049 with TLS
  (ISE's default, not RFC 9887's 300; ise-cpp relies on it). `check_tls()` refuses contexts that allow TLS < 1.3 or
  don't verify the server. In the sync client, check `sock.pending()` before
  `select()`: decrypted data can sit in the SSL buffer, where select doesn't see it.
  The TLS tests make their certificates with the `openssl` command
  (`tests/conftest.py`) and are skipped without it.
- **A `session_id` passed to `TACACSClient()` is used for every session.** It exists for
  tests; don't pass one in real code.
- **Errors:** `TimeoutError` when no reply comes in time, `TACACSProtocolError` (a
  subclass of `OSError`) for a reply that isn't TACACS+, a garbled one (the clients
  parse with `unpacked(..., strict=True)`: length fields must fit the body, trailing
  bytes are allowed, the status must be known; a wrong secret shows up here) or a
  connection closed mid-packet,
  other `OSError`s from the socket, `ValueError` for bad arguments.
- **ruff reads `ruff.toml`**, not `setup.cfg`; it lists `bin/tacacs_client` (no `.py`)
  in `extend-include`, so `ruff check .` covers it.
- **Tests:** `pip install -e . -r requirements-dev.txt`, then `pytest` from
  the repo root. `setup.cfg` adds coverage options, so pytest needs `pytest-cov`.
  `tests/` is excluded from the wheel.

## Known issues

Not yet fixed; don't assume otherwise.

- ISE 3.4p7 was probed with ise-cpp's `tools/tacacs_probe.py` (its own protocol code,
  no TLS): CHAP, ASCII login, the expired-password dialog and CHPASS all work, passwords
  are compared as UTF-8, and the prompts (replayed in `tests/test_authen_dialog.py`,
  `test_ise_*`) match `authen_dialog.py`. Not yet run against ISE: this library's
  `change_password()`/`new_password`, and any password change over TLS.
- TACACS+ over TLS against ISE: only an ASCII login (CLI, TLS 1.3) has been tried, and it
  passed. ISE requires a client certificate whose subjectAltName has the client's source
  IP (see the "Cisco ISE" section of `docs/guide/tls.rst`). Without TLS, obfuscation is
  MD5-based (RFC 8907 says to use TACACS+ only on secure networks).
- Single-connection mode (`TAC_PLUS_SINGLE_CONNECT_FLAG`) is left out on purpose: ise-cpp
  makes a few requests a minute, so one connection per session costs nothing, while
  reusing connections needs open-connection handling, reconnects and thread safety.
  Ask the user before implementing it. FOLLOW and RESTART replies aren't acted on
  (no retry, no other server); as RFC 8907 says, `reply.invalid` is true for them
  (authorization: FOLLOW), and `reply.restart`/`reply.follow` tell them apart from
  FAIL (see `docs/about.rst`).
- Certificate revocation (RFC 9887 asks for it) is only checked if the caller loads
  CRLs into the context; OCSP isn't supported (see `tls_context()`).
