#!/usr/bin/env python3
"""
Forces the card in the first available reader into the unpowered state via
PC/SC SCARD_UNPOWER_CARD. Run immediately before a wallet command to simulate
the power-loss condition reported on some USB reader/driver combinations.

Either:
- pcscd re-powers the card on the next SCardConnect, so wallet
commands will succeed without triggering the retry path.
- the card stays unpowered, triggering TransportError
and exercising the retry wrapper in pair() / setup_communication_with_pairing().
"""
import sys
from smartcard.scard import (
    SCardEstablishContext, SCardListReaders, SCardConnect, SCardDisconnect,
    SCARD_SCOPE_USER, SCARD_SHARE_SHARED,
    SCARD_PROTOCOL_T0, SCARD_PROTOCOL_T1,
    SCARD_UNPOWER_CARD,
)

hresult, hcontext = SCardEstablishContext(SCARD_SCOPE_USER)
hresult, reader_list = SCardListReaders(hcontext, [])

if not reader_list:
    print("force_unpower: no readers found, skipping.")
    sys.exit(0)

hresult, hcard, _ = SCardConnect(
    hcontext,
    reader_list[0],
    SCARD_SHARE_SHARED,
    SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
)

if hresult != 0:
    print(f"force_unpower: SCardConnect failed (hresult={hresult:#010x}), skipping.")
    sys.exit(0)

SCardDisconnect(hcard, SCARD_UNPOWER_CARD)
print("force_unpower: card powered down.")
