from bonsai._bonsai import (
    get_tls_impl_name,
    set_connect_async,
    get_vendor_info,
    has_krb5_support,
    _unique_contains,
    set_debug,
)


def escape_attribute_value(attrval: str) -> str:
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
        attrval = attrval.replace(char, f"\\{char}")
    if attrval[0] == "#" or attrval[0] == " ":
        attrval = "".join(("\\", attrval))
    if attrval[-1] == " ":
        attrval = "".join((attrval[:-1], "\\ "))
    attrval = attrval.replace("\0", "\\0")
    return attrval


def escape_filter_exp(filter_exp: str) -> str:
    """
    Escapes the special characters in an LDAP filter based on RFC 4515.

    :param str filter_exp: the unescaped filter expression.
    :return: the escaped filter expression.
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
        filter_exp = filter_exp.replace(char, repl)
    return filter_exp
