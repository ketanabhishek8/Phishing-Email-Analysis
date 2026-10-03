"""Make email-controlled text safe to display.

Attackers put invisible characters in subjects, names and filenames: right-to-left
overrides that disguise 'invoice‮fdp.exe' as 'invoiceexe.pdf', zero-width
characters that split keywords, and terminal escape sequences that can rewrite what an
analyst sees in a console. These helpers turn all of them into visible markers.
"""

from __future__ import annotations

import re

# Bidirectional controls and zero-width / invisible formatting characters.
BIDI_CONTROLS = re.compile("[‪-‮⁦-⁩‎‏؜]")
INVISIBLE = re.compile("[‪-‮⁦-⁩​-‏؜⁠-⁤﻿]")
# C0 controls except tab/newline/carriage return, DEL, and C1 controls.
CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def reveal(text: str) -> str:
    """Replace invisible formatting characters with a visible <U+XXXX> marker."""
    return INVISIBLE.sub(lambda m: f"<U+{ord(m.group(0)):04X}>", text)


def for_terminal(text: str) -> str:
    """reveal() plus escaping of control characters such as ESC (\\x1b)."""
    return CONTROL.sub(lambda m: f"\\x{ord(m.group(0)):02x}", reveal(str(text)))
