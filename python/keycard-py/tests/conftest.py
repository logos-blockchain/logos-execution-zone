import pytest
from unittest.mock import Mock
from keycard.card_interface import CardInterface


@pytest.fixture
def card():
    mock = Mock(spec=CardInterface)
    return mock
