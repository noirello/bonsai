import pytest

from bonsai.utils import escape_filter
from bonsai.utils import escape_attribute_value


def test_escape_attribute_value():
    """ Test escaping special characters in attribute values. """
    assert (
        escape_attribute_value(" dummy=test,something+somethingelse")
        == r"\ dummy\=test\,something\+somethingelse"
    )
    assert escape_attribute_value("#dummy=test ") == r"\#dummy\=test\ "
    assert escape_attribute_value(r"term\0") == r"term\\0"


def test_escape_filter():
    """ Test escaping filter expressions. """
    assert escape_filter("(parenthesis)") == "\\28parenthesis\\29"
    assert escape_filter("cn=*") == "cn=\\2A"
    assert escape_filter("\\backslash") == "\\5Cbackslash"
    assert escape_filter("term\0") == "term\\0"
