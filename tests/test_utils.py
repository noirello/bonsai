import pytest

from bonsai.utils import escape_filter_exp
from bonsai.utils import escape_attribute_value
from bonsai.utils import set_connect_async


def test_escape_attribute_value():
    """ Test escaping special characters in attribute values. """
    assert (
        escape_attribute_value(" dummy=test,something+somethingelse")
        == r"\ dummy\=test\,something\+somethingelse"
    )
    assert escape_attribute_value("#dummy=test ") == r"\#dummy\=test\ "
    assert escape_attribute_value(r"term\0") == r"term\\0"


def test_escape_filter_exp():
    """ Test escaping filter expressions. """
    assert escape_filter_exp("(parenthesis)") == "\\28parenthesis\\29"
    assert escape_filter_exp("cn=*") == "cn=\\2A"
    assert escape_filter_exp("\\backslash") == "\\5Cbackslash"
    assert escape_filter_exp("term\0") == "term\\0"


def test_set_async_connect(client):
    """ Dummy test for set_connect_async. """
    with pytest.raises(TypeError):
        set_connect_async("true")
    set_connect_async(False)
    conn = client.connect()
    assert conn is not None