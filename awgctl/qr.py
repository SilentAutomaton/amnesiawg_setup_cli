"""Terminal QR code, if the optional segno package is installed."""

from __future__ import annotations


def print_qr(text: str) -> None:
    try:
        import segno
    except ImportError:
        print("install the qr extra for a scannable code: pip install 'awgctl[qr]'")
        return
    segno.make(text).terminal(compact=True)
