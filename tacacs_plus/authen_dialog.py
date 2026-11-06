"""
Authentication logic shared by client.TACACSClient and
async_client.TACACSClient: the data of an authentication START, and the
answers to the server's ASCII dialog (GETUSER/GETPASS/GETDATA).
"""
import re
from hashlib import md5

from .flags import (
    TAC_PLUS_AUTHEN_TYPE_CHAP, TAC_PLUS_AUTHEN_TYPE_PAP, TAC_PLUS_MINOR_VER_ONE
)
from .packet import to_bytes

# prompt texts in GETPASS/GETDATA replies, see prompt_kind()
PASSWORD_PROMPT = re.compile(r'pass|secret|\bpin\b', re.I)
NEW_PASSWORD_PROMPT = re.compile(r'\bnew\b|confirm|re-?enter|re-?type|again|verify', re.I)
OLD_PASSWORD_PROMPT = re.compile(r'\bold\b|current|existing', re.I)
USER_PROMPT = re.compile(r'user|login', re.I)

# how often each kind of answer is sent before the client gives up on the
# dialog: the password twice (login, then an explicit "old password" when
# it must be changed), the new password twice (new + confirmation)
ANSWER_LIMITS = {'user': 1, 'old': 2, 'new': 2}


def start_data(authen_type, password, chap_ppp_id, chap_challenge, encoding):
    """
    The data of an authentication START and its minor version: the password
    for PAP, the CHAP ID, challenge and response for CHAP, nothing for ASCII
    (minor version None: the client's default).

    :raises: ValueError for a missing password or bad CHAP arguments
    """
    if authen_type not in (TAC_PLUS_AUTHEN_TYPE_PAP, TAC_PLUS_AUTHEN_TYPE_CHAP):
        return b'', None
    if not password:
        raise ValueError('a password is required for PAP and CHAP')
    if authen_type == TAC_PLUS_AUTHEN_TYPE_PAP:
        return to_bytes(password, encoding), TAC_PLUS_MINOR_VER_ONE

    if not isinstance(chap_ppp_id, str):
        raise ValueError('chap_ppp_id must be a string')
    if len(chap_ppp_id) != 1:
        raise ValueError('chap_ppp_id must be a 1-byte string')
    if not isinstance(chap_challenge, str):
        raise ValueError('chap_challenge must be a string')
    if len(chap_challenge) > 255:
        raise ValueError('chap_challenge may not be more 255 bytes')
    ppp_id, challenge = to_bytes(chap_ppp_id), to_bytes(chap_challenge)
    response = md5(ppp_id + to_bytes(password, encoding) + challenge).digest()
    return ppp_id + challenge + response, TAC_PLUS_MINOR_VER_ONE


def prompt_kind(reply, server_msg, sent):
    """
    Guess what the server asks for: 'user', 'old' (the current password),
    'new' (a new password or its confirmation) or None (unknown).

    Password prompts are told apart by their text ("new", "confirm", "old",
    ...); when the text doesn't say, the first one is the current password
    and later ones the new password.
    """
    if reply.getuser:
        return 'user'
    if reply.getpass or reply.noecho or PASSWORD_PROMPT.search(server_msg):
        if NEW_PASSWORD_PROMPT.search(server_msg):
            return 'new'
        if OLD_PASSWORD_PROMPT.search(server_msg):
            return 'old'
        return 'old' if not sent['old'] else 'new'
    if USER_PROMPT.search(server_msg):
        return 'user'
    return None


class AuthenDialog:
    """
    The answers for one ASCII dialog.

    Each reply is answered with the username, the (old) password or the new
    password, see prompt_kind(); each kind at most ANSWER_LIMITS times, and
    at most `max_steps` answers in all.  The clients run it like this, and
    abort the session when there is no answer:

        while dialog.asks(reply):
            kind, answer = dialog.known_answer(reply)
            if answer is None and prompt is not None and dialog.steps_left:
                answer = prompt(dialog.server_msg(reply), not reply.noecho)
            if answer is None or not dialog.steps_left:
                ... abort
            dialog.answered(kind)
            ... send CONTINUE(answer), read the next reply
    """

    def __init__(self, username, password, new_password, max_steps, encoding):
        self.values = {'user': username, 'old': password, 'new': new_password}
        self.sent = dict.fromkeys(self.values, 0)
        self.steps = 0
        self.max_steps = max_steps
        self.encoding = encoding

    @staticmethod
    def asks(reply):
        return reply.getuser or reply.getpass or reply.getdata

    def server_msg(self, reply):
        return reply.server_msg.decode(self.encoding, 'replace')

    @property
    def steps_left(self):
        return self.steps < self.max_steps

    def known_answer(self, reply):
        """(kind, answer) for `reply`; answer is None when there is none (left)."""
        kind = prompt_kind(reply, self.server_msg(reply), self.sent)
        if kind and self.sent[kind] < ANSWER_LIMITS[kind]:
            return kind, self.values[kind]
        return kind, None

    def answered(self, kind):
        if kind:
            self.sent[kind] += 1
        self.steps += 1
