"""QR codes (v0.14.0), for the two-factor setup page and anything else.

    Qr.svg("otpauth://totp/...")            an <svg> string, ready for {!...!} in a view
    Qr.svg(text, #{"size": 240, "margin": 4, "color": "#111", "background": "#fff"})
    Qr.matrix(text)                         list<list<bool>>, true = dark, no quiet zone

Byte mode, error correction level M (15% of the code can be damaged), versions
1-10 (up to 213 bytes). The layout follows ISO/IEC 18004.
"""

from barq.builtins import need
from barq.runtime import to_display
from barq.stdlib import arg

# ---- GF(256) and Reed-Solomon ------------------------------------------------

EXP = [0] * 512
LOG = [0] * 256
_x = 1
for _k in range(255):
    EXP[_k] = _x
    LOG[_x] = _k
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _k in range(255, 512):
    EXP[_k] = EXP[_k - 255]


def gmul(a, b):
    return 0 if a == 0 or b == 0 else EXP[LOG[a] + LOG[b]]


def rs_generator(degree):
    g = [1]
    for k in range(degree):
        nxt = [0] * (len(g) + 1)
        for j, c in enumerate(g):
            nxt[j] ^= c
            nxt[j + 1] ^= gmul(c, EXP[k])
        g = nxt
    return g


def rs_remainder(data, degree):
    g = rs_generator(degree)
    res = list(data) + [0] * degree
    for k in range(len(data)):
        coef = res[k]
        if coef:
            for j in range(1, len(g)):
                res[k + j] ^= gmul(g[j], coef)
    return res[len(data):]


# ---- version tables (level M) -----------------------------------------------

# version: (EC codewords per block, [(blocks, data codewords per block), ...])
BLOCKS_M = {
    1: (10, [(1, 16)]),
    2: (16, [(1, 28)]),
    3: (26, [(1, 44)]),
    4: (18, [(2, 32)]),
    5: (24, [(2, 43)]),
    6: (16, [(4, 27)]),
    7: (18, [(4, 31)]),
    8: (22, [(2, 38), (2, 39)]),
    9: (22, [(3, 36), (2, 37)]),
    10: (26, [(4, 43), (1, 44)]),
}
ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42],
         9: [6, 26, 46], 10: [6, 28, 50]}
MAX_VERSION = 10
FORMAT_M = 0     # error correction level bits: L=1, M=0, Q=3, H=2


def data_capacity(version):
    return sum(b * d for b, d in BLOCKS_M[version][1])


def count_bits(version):
    return 8 if version <= 9 else 16


def pick_version(length):
    for v in range(1, MAX_VERSION + 1):
        if 4 + count_bits(v) + 8 * length <= data_capacity(v) * 8:
            return v
    return None


def data_codewords(data, version):
    bits = []

    def put(value, width):
        bits.extend((value >> k) & 1 for k in range(width - 1, -1, -1))
    put(0b0100, 4)                      # byte mode
    put(len(data), count_bits(version))
    for b in data:
        put(b, 8)
    cap = data_capacity(version) * 8
    bits.extend([0] * min(4, cap - len(bits)))
    bits.extend([0] * (-len(bits) % 8))
    out = [int("".join(map(str, bits[k:k + 8])), 2) for k in range(0, len(bits), 8)]
    pad = (0xEC, 0x11)
    while len(out) < data_capacity(version):
        out.append(pad[(len(out) - len(bits) // 8) % 2])
    return out


def interleave(cw, version):
    ec_len, groups = BLOCKS_M[version]
    blocks, pos = [], 0
    for count, size in groups:
        for _ in range(count):
            blocks.append(cw[pos:pos + size])
            pos += size
    ecs = [rs_remainder(b, ec_len) for b in blocks]
    out = []
    for k in range(max(len(b) for b in blocks)):
        out.extend(b[k] for b in blocks if k < len(b))
    for k in range(ec_len):
        out.extend(e[k] for e in ecs)
    return out


# ---- the matrix ---------------------------------------------------------------

class Grid:
    def __init__(self, version):
        self.size = 17 + 4 * version
        self.dark = [[False] * self.size for _ in range(self.size)]
        self.fixed = [[False] * self.size for _ in range(self.size)]

    def set(self, x, y, dark):
        self.dark[y][x] = dark
        self.fixed[y][x] = True


def draw_function_patterns(g, version):
    size = g.size
    for k in range(size):                       # timing patterns
        g.set(6, k, k % 2 == 0)
        g.set(k, 6, k % 2 == 0)
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):     # finders + separators
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                x, y = cx + dx, cy + dy
                if 0 <= x < size and 0 <= y < size:
                    d = max(abs(dx), abs(dy))
                    g.set(x, y, d not in (2, 4))
    pos = ALIGN[version]
    for a in pos:
        for b in pos:
            if (a == 6 and b == 6) or (a == 6 and b == pos[-1]) or (a == pos[-1] and b == 6):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    g.set(a + dx, b + dy, max(abs(dx), abs(dy)) != 1)
    draw_format(g, 0)                           # reserve the format areas
    if version >= 7:
        rem = version
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        bits = version << 12 | rem
        for k in range(18):
            bit = (bits >> k) & 1 == 1
            a, b = size - 11 + k % 3, k // 3
            g.set(a, b, bit)
            g.set(b, a, bit)


def draw_format(g, mask):
    data = FORMAT_M << 3 | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    bits = (data << 10 | rem) ^ 0x5412
    size = g.size

    def bit(k):
        return (bits >> k) & 1 == 1
    for k in range(6):
        g.set(8, k, bit(k))
    g.set(8, 7, bit(6))
    g.set(8, 8, bit(7))
    g.set(7, 8, bit(8))
    for k in range(9, 15):
        g.set(14 - k, 8, bit(k))
    for k in range(8):
        g.set(size - 1 - k, 8, bit(k))
    for k in range(8, 15):
        g.set(8, size - 15 + k, bit(k))
    g.set(8, size - 8, True)                    # the dark module


def place_data(g, cw):
    size, k, total = g.size, 0, len(cw) * 8
    right = size - 1
    while right >= 1:
        if right == 6:
            right = 5
        for vert in range(size):
            for j in range(2):
                x = right - j
                upward = ((right + 1) & 2) == 0
                y = size - 1 - vert if upward else vert
                if not g.fixed[y][x] and k < total:
                    g.dark[y][x] = (cw[k >> 3] >> (7 - (k & 7))) & 1 == 1
                    k += 1
        right -= 2


MASKS = [
    lambda x, y: (x + y) % 2 == 0,
    lambda x, y: y % 2 == 0,
    lambda x, y: x % 3 == 0,
    lambda x, y: (x + y) % 3 == 0,
    lambda x, y: (x // 3 + y // 2) % 2 == 0,
    lambda x, y: x * y % 2 + x * y % 3 == 0,
    lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
    lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
]


def apply_mask(g, mask):
    f = MASKS[mask]
    for y in range(g.size):
        for x in range(g.size):
            if not g.fixed[y][x] and f(x, y):
                g.dark[y][x] = not g.dark[y][x]


FINDER_A = [True, False, True, True, True, False, True, False, False, False, False]
FINDER_B = FINDER_A[::-1]


def penalty(m):
    size, score = len(m), 0
    lines = [row for row in m] + [[m[y][x] for y in range(size)] for x in range(size)]
    for line in lines:
        run, prev = 0, None
        for v in line:
            if v == prev:
                run += 1
            else:
                if run >= 5:
                    score += run - 2
                run, prev = 1, v
        if run >= 5:
            score += run - 2
        for k in range(size - 10):
            seg = line[k:k + 11]
            if seg == FINDER_A or seg == FINDER_B:
                score += 40
    for y in range(size - 1):
        for x in range(size - 1):
            c = m[y][x]
            if c == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                score += 3
    dark = sum(sum(row) for row in m)
    score += abs(dark * 100 // (size * size) - 50) // 5 * 10
    return score


def encode(text):
    """-> list of rows of bools, or None when the text is too long."""
    data = text.encode("utf-8")
    version = pick_version(len(data))
    if version is None:
        return None
    cw = interleave(data_codewords(data, version), version)
    best = None
    for mask in range(8):
        g = Grid(version)
        draw_function_patterns(g, version)
        place_data(g, cw)
        apply_mask(g, mask)
        draw_format(g, mask)
        score = penalty(g.dark)
        if best is None or score < best[0]:
            best = (score, g.dark)
    return best[1]


def svg(matrix, size=None, margin=4, color="#000", background="#fff"):
    w = len(matrix) + 2 * margin
    parts = []
    for y, row in enumerate(matrix):
        x = 0
        while x < len(row):
            if row[x]:
                start = x
                while x < len(row) and row[x]:
                    x += 1
                parts.append(f"M{start + margin},{y + margin}h{x - start}v1h-{x - start}z")
            else:
                x += 1
    dims = f' width="{size}" height="{size}"' if size else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {w}"{dims} shape-rendering="crispEdges">'
            f'<rect width="{w}" height="{w}" fill="{background}"/><path fill="{color}" d="{"".join(parts)}"/></svg>')


# ---- the Qr module ----------------------------------------------------------------

def need_matrix(i, a, n, fname):
    text = need(i, a[0], ("string",), fname, 1, n)
    m = encode(text)
    if m is None:
        i.throw("ValueException", f"{fname}(): the text is too long for a QR code here "
                f"({len(text.encode('utf-8'))} bytes; the limit is {data_capacity(MAX_VERSION) - 3})", n)
    return m


SVG_OPTIONS = ("size", "margin", "color", "background")
COLOR_RE = r"^(#[0-9A-Fa-f]{3,8}|[a-zA-Z]+|currentColor)$"


def qr_svg(i, a, n):
    import re
    m = need_matrix(i, a, n, "Qr.svg")
    opts = arg(i, a, 1, ("dict",), "Qr.svg", n, {})
    for k in opts:
        if k not in SVG_OPTIONS:
            i.throw("ValueException", f'Qr.svg(): unknown option "{k}" (use {", ".join(SVG_OPTIONS)})', n)
    size = opts.get("size")
    margin = opts.get("margin", 4)
    if size is not None and (type(size) is not int or size <= 0):
        i.throw("ValueException", f"Qr.svg(): size must be a positive int, got {to_display(size, i, True)}", n)
    if type(margin) is not int or margin < 0:
        i.throw("ValueException", f"Qr.svg(): margin must be an int >= 0, got {to_display(margin, i, True)}", n)
    colors = {}
    for k, default in (("color", "#000"), ("background", "#fff")):
        v = opts.get(k, default)
        if not isinstance(v, str) or not re.match(COLOR_RE, v):
            i.throw("ValueException", f'Qr.svg(): {k} must be a color like "#1a7f37", got {to_display(v, i, True)}', n)
        colors[k] = v
    return svg(m, size, margin, colors["color"], colors["background"])


QR = {
    "svg": (qr_svg, 1, 2),
    "matrix": (lambda i, a, n: [list(row) for row in need_matrix(i, a, n, "Qr.matrix")], 1, 1),
}
