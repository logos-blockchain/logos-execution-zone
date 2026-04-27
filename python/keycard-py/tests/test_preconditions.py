import pytest
from keycard.card_interface import CardInterface
from keycard.preconditions import make_precondition
from keycard.exceptions import InvalidStateError


class DummyCard(CardInterface):
    def __init__(self, **attrs):
        for k, v in attrs.items():
            setattr(self, k, v)


def test_precondition_passes_when_attribute_true():
    @make_precondition('is_ready')
    def do_something(card):
        return "success"
    card = DummyCard(is_ready=True)
    assert do_something(card) == "success"


def test_precondition_raises_when_attribute_false():
    @make_precondition('is_ready')
    def do_something(card):
        return "should not reach"
    card = DummyCard(is_ready=False)
    with pytest.raises(InvalidStateError) as exc:
        do_something(card)
    assert "Is Ready must be satisfied." in str(exc.value)


def test_precondition_raises_when_attribute_missing():
    @make_precondition('is_ready')
    def do_something(card):
        return "should not reach"
    card = DummyCard()
    with pytest.raises(InvalidStateError) as exc:
        do_something(card)
    assert "Is Ready must be satisfied." in str(exc.value)


def test_precondition_custom_display_name():
    @make_precondition('is_ready', display_name="Custom Name")
    def do_something(card):
        return "success"
    card = DummyCard(is_ready=False)
    with pytest.raises(InvalidStateError) as exc:
        do_something(card)
    assert "Custom Name must be satisfied." in str(exc.value)


def test_precondition_passes_args_kwargs():
    @make_precondition('is_ready')
    def do_something(card, x, y=2):
        return x + y
    card = DummyCard(is_ready=True)
    assert do_something(card, 3, y=4) == 7
