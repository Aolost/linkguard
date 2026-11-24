"""Build look-alike and invisible characters from code points.

Writing them literally would put invisible or confusable characters into the source
of a tool whose job is to flag them.
"""


def text(*codepoints: int) -> str:
    return "".join(chr(codepoint) for codepoint in codepoints)


def fullwidth(ascii_text: str) -> str:
    """Full-width forms of ASCII letters and digits, with the ideographic full stop."""
    return "".join(
        chr(0xFF0E) if char == "." else chr(ord(char) + 0xFEE0) for char in ascii_text
    )


NO_BREAK_SPACE = text(0xA0)
LINE_SEPARATOR = text(0x2028)
RIGHT_TO_LEFT_OVERRIDE = text(0x202E)
U_DIAERESIS = text(0xFC)
SHARP_S = text(0xDF)
