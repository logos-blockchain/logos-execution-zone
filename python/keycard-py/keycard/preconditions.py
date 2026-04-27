from functools import wraps
from typing import Callable, TypeVar, ParamSpec, cast

from .exceptions import InvalidStateError
from .card_interface import CardInterface

P = ParamSpec("P")
R = TypeVar("R")


def make_precondition(
    attribute_name: str,
    display_name: str | None = None
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            card = args[0]
            if not isinstance(card, CardInterface):
                raise TypeError("First argument must be a CardInterface")
            if not getattr(card, attribute_name, False):
                readable = (
                    display_name
                    if display_name is not None
                    else attribute_name.replace('_', ' ').title()
                )
                raise InvalidStateError(f"{readable} must be satisfied.")
            return func(*args, **kwargs)
        return cast(Callable[P, R], wrapper)
    return decorator


require_selected = make_precondition(
    'is_selected',
    'Card Selection'
)
require_initialized = make_precondition(
    'is_initialized',
    'Card Initialization'
)
require_secure_channel = make_precondition(
    'is_secure_channel_open',
    'Secure Channel'
)
require_pin_verified = make_precondition(
    'is_pin_verified',
    'PIN verification'
)
