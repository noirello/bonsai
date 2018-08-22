from ._bonsai import (
    get_tls_impl_name,
    get_vendor_info,
    has_krb5_support,
    _unique_contains,
    set_debug,
)


def escape_attribute_value(attrval: str):
    """
    Escapes the special character in an attribute value
    based on RFC 4514.

    :param str attrval: the attribute value.
    :return: The escaped attribute value.
    :rtype: str
    """
    # Order matters.
    chars_to_escape = ("\\", '"', "+", ",", ";", "<", "=", ">")
    for char in chars_to_escape:
        attrval = attrval.replace(char, "\\{0}".format(char))
    if attrval[0] == "#" or attrval[0] == " ":
        attrval = "".join(("\\", attrval))
    if attrval[-1] == " ":
        attrval = "".join((attrval[:-1], "\\ "))
    attrval = attrval.replace("\0", "\\0")
    return attrval


def escape_filter(fltstr: str):
    """
    Escapes the special characters in an LDAP filter based on RFC 4515.

    :param str fltstr: the unescaped filter string.
    :return: the escaped filter string.
    :rtype: str
    """
    chars_to_escape = (
        ("\\", "\\5C"),
        ("*", "\\2A"),
        ("(", "\\28"),
        (")", "\\29"),
        ("\0", "\\0"),
    )
    for char, repl in chars_to_escape:
        fltstr = fltstr.replace(char, repl)
    return fltstr
