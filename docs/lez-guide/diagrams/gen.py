#!/usr/bin/env python3
"""Generates the execution diagrams under src/diagrams/.

Grammar: one column per step. The upper band ("hidden") holds what stays with the participants,
the lower band ("on chain") what everyone can see. Each band holds at most a few short chips.
A dashed arrow is a private transaction, a solid one a signed public transaction.
Run from anywhere: `python3 diagrams/gen.py`.
"""

import os
from html import escape

from specs import DIAGRAMS

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "diagrams")

COL_W = 160
GAP = 12
GUTTER = 0
CAPTION = 16  # band label above the chips
MARGIN = 12
CHIP_H = 24
CHIP_GAP = 6
BAND_PAD = 10
MAX_COLS = 99  # no wrapping: wide diagrams keep their size and scroll sideways

PRIV = "#4f86c6"
PRIV_CHIP = "rgba(79,134,198,0.18)"
PRIV_BAND = "rgba(79,134,198,0.07)"
PUB = "#d9912b"
PUB_CHIP = "rgba(217,145,43,0.20)"
PUB_BAND = "rgba(217,145,43,0.07)"
REFUSED = "#c9504a"
MUTED = "rgba(128,128,128,0.95)"
FG = "fill:var(--fg, #333)"

NOTES = "only unlinkable notes"


def text(x, y, s, size=12, weight="normal", style=FG, anchor="start", italic=False):
    italic_css = "font-style:italic;" if italic else ""
    return (
        f'<text x="{x:.0f}" y="{y:.0f}" font-size="{size}" font-weight="{weight}" '
        f'text-anchor="{anchor}" style="{style};{italic_css}font-family:inherit">{escape(s)}</text>'
    )


def chip(x, y, label, kind):
    if label == NOTES:
        return [
            f'<rect x="{x}" y="{y}" width="{COL_W}" height="{CHIP_H}" rx="12" '
            f'style="fill:none;stroke:{MUTED};stroke-dasharray:3,3"/>',
            text(x + COL_W / 2, y + 16, label, style=f"fill:{MUTED}", anchor="middle", italic=True),
        ]
    fill, stroke = (PRIV_CHIP, PRIV) if kind == "hidden" else (PUB_CHIP, PUB)
    if kind == "refused":
        fill, stroke = "rgba(201,80,74,0.12)", REFUSED
    if kind == "offchain":
        fill, stroke = "rgba(128,128,128,0.10)", MUTED
    return [
        f'<rect x="{x}" y="{y}" width="{COL_W}" height="{CHIP_H}" rx="12" '
        f'style="fill:{fill};stroke:{stroke};stroke-width:1.1"/>',
        text(x + COL_W / 2, y + 16, label, anchor="middle"),
    ]


def band_height(n):
    return CAPTION + BAND_PAD * 2 + max(n, 1) * CHIP_H + max(n - 1, 0) * CHIP_GAP


def rows_of(cols):
    n_rows = -(-len(cols) // MAX_COLS)
    per_row = -(-len(cols) // n_rows)
    return [cols[k:k + per_row] for k in range(0, len(cols), per_row)]


def block(cols, top, width):
    out = []
    head_h = 46
    n_hidden = max(len(c.get("hidden", [])) for c in cols)
    n_chain = max(len(c.get("chain", [])) for c in cols)
    h_top = top + head_h
    h_h = band_height(n_hidden)
    arrow = 30
    c_top = h_top + h_h + arrow
    c_h = band_height(n_chain)
    band_w = width - MARGIN * 2

    out.append(f'<rect x="{MARGIN}" y="{h_top}" width="{band_w}" height="{h_h}" rx="8" style="fill:{PRIV_BAND}"/>')
    out.append(text(MARGIN + 8, h_top + 13, "HIDDEN", size=10, weight="bold", style=f"fill:{PRIV}"))
    out.append(f'<rect x="{MARGIN}" y="{c_top}" width="{band_w}" height="{c_h}" rx="8" style="fill:{PUB_BAND}"/>')
    out.append(text(MARGIN + 8, c_top + 13, "ON CHAIN", size=10, weight="bold", style=f"fill:{PUB}"))

    for i, col in enumerate(cols):
        x = MARGIN + GUTTER + i * (COL_W + GAP)
        cx = x + COL_W / 2
        tx = col["tx"]
        out.append(text(cx, top + 16, col["head"], size=13, weight="bold", anchor="middle"))
        who_color = {"private": PRIV, "public": PUB, "refused": REFUSED}.get(tx, MUTED)
        out.append(text(cx, top + 34, col.get("who", ""), size=12, style=f"fill:{who_color}", anchor="middle"))

        hidden = col.get("hidden", [])
        if hidden:
            for k, label in enumerate(hidden):
                out.extend(chip(x, h_top + CAPTION + BAND_PAD + k * (CHIP_H + CHIP_GAP), label,
                                "offchain" if tx == "offchain" else "hidden"))
        else:
            out.append(text(cx, h_top + CAPTION + BAND_PAD + 16, "nothing", style=f"fill:{MUTED}", anchor="middle", italic=True))

        a_top, a_bot = h_top + h_h + 3, c_top - 3
        if tx in ("private", "refused", "public"):
            color = PUB if tx == "public" else PRIV
            dash = "none" if tx == "public" else "5,4"
            out.append(f'<line x1="{cx}" y1="{a_top}" x2="{cx}" y2="{a_bot - 7}" '
                       f'style="stroke:{color};stroke-width:1.8;stroke-dasharray:{dash}"/>')
            out.append(f'<polygon points="{cx - 5},{a_bot - 8} {cx + 5},{a_bot - 8} {cx},{a_bot}" style="fill:{color}"/>')

        if tx == "offchain":
            out.append(text(cx, (a_top + a_bot) / 2 + 4, "no transaction", size=11,
                            style=f"fill:{MUTED}", anchor="middle", italic=True))

        chain = col.get("chain", [])
        kind = "refused" if tx == "refused" else "chain"
        if chain:
            for k, label in enumerate(chain):
                out.extend(chip(x, c_top + CAPTION + BAND_PAD + k * (CHIP_H + CHIP_GAP), label, kind))
        else:
            out.append(text(cx, c_top + CAPTION + BAND_PAD + 16, "nothing", style=f"fill:{MUTED}", anchor="middle", italic=True))

    return out, c_top + c_h - top


def render(spec):
    rows = rows_of(spec["columns"])
    per_row = max(len(r) for r in rows)
    width = MARGIN * 2 + GUTTER + per_row * COL_W + (per_row - 1) * GAP
    out, y = [], 28
    body = []
    if spec.get("subtitle"):
        y = 48
    for r, cols in enumerate(rows):
        top = y + (10 if r == 0 else 22)
        elements, h = block(cols, top, width)
        body.extend(elements)
        y = top + h
    height = y + MARGIN

    out.append('<div style="overflow-x:auto;margin:1.2em 0">')
    out.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" '
               f'height="{height}" style="display:block;max-width:none" role="img" '
               f'aria-label="{escape(spec["title"])}">')
    out.append(f"<title>{escape(spec['title'])}</title>")
    out.append(text(MARGIN, 22, spec["title"], size=15, weight="bold"))
    if spec.get("subtitle"):
        out.append(text(MARGIN, 42, spec["subtitle"], size=12, style=f"fill:{MUTED}"))
    out.extend(body)
    out.append("</svg>")
    out.append("</div>")
    return "\n".join(out) + "\n"


def legend():
    w, h = 790, 70
    out = [
        '<div style="overflow-x:auto;margin:1.2em 0">',
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
        f'style="display:block;max-width:none" role="img" aria-label="Diagram legend">',
        "<title>Diagram legend</title>",
        f'<rect x="4" y="6" width="120" height="24" rx="12" style="fill:{PRIV_CHIP};stroke:{PRIV}"/>',
        text(64, 22, "hidden", anchor="middle"),
        f'<rect x="136" y="6" width="120" height="24" rx="12" style="fill:{PUB_CHIP};stroke:{PUB}"/>',
        text(196, 22, "on chain", anchor="middle"),
        f'<rect x="268" y="6" width="170" height="24" rx="12" style="fill:none;stroke:{MUTED};stroke-dasharray:3,3"/>',
        text(353, 22, NOTES, style=f"fill:{MUTED}", anchor="middle", italic=True),
        f'<rect x="450" y="6" width="120" height="24" rx="12" style="fill:rgba(201,80,74,0.12);stroke:{REFUSED}"/>',
        text(510, 22, "refused", anchor="middle"),
        f'<rect x="582" y="6" width="120" height="24" rx="12" style="fill:rgba(128,128,128,0.10);stroke:{MUTED}"/>',
        text(642, 22, "off chain", anchor="middle"),
        f'<line x1="8" y1="54" x2="44" y2="54" style="stroke:{PRIV};stroke-width:1.8;stroke-dasharray:5,4"/>',
        text(52, 58, "private transaction (proof)"),
        f'<line x1="250" y1="54" x2="286" y2="54" style="stroke:{PUB};stroke-width:1.8"/>',
        text(294, 58, "public transaction (signed)"),
        text(500, 58, "no arrow: nothing is sent to the chain", style=f"fill:{MUTED}", italic=True),
        "</svg>",
        "</div>",
    ]
    return "\n".join(out) + "\n"


def main():
    os.makedirs(OUT, exist_ok=True)
    for name in os.listdir(OUT):
        if name.endswith(".svg"):
            os.remove(os.path.join(OUT, name))
    with open(os.path.join(OUT, "legend.svg"), "w") as f:
        f.write(legend())
    for spec in DIAGRAMS:
        for col in spec["columns"]:
            for label in col.get("hidden", []) + col.get("chain", []):
                assert len(label) <= 24, f"{spec['id']}: chip too long: {label!r}"
        assert len(spec.get("subtitle", "")) <= 95, f"{spec['id']}: subtitle too long"
        with open(os.path.join(OUT, spec["id"] + ".svg"), "w") as f:
            f.write(render(spec))
    print(f"wrote {len(DIAGRAMS) + 1} diagrams to {os.path.normpath(OUT)}")


if __name__ == "__main__":
    main()
