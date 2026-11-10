"""Print an SVG <path> for TEXT set in Archivo at weight 800, the same
placement as <text x=X y=Y font-size=SIZE letter-spacing=LS>."""
import sys

import uharfbuzz as hb
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

font_path, text = sys.argv[1], "corten"
X, Y, SIZE, LS = 222, 140, 120, -3

tt = instantiateVariableFont(TTFont(font_path), {"wght": 800, "wdth": 100})
upem = tt["head"].unitsPerEm
scale = SIZE / upem

blob = hb.Blob.from_file_path(font_path)
face = hb.Face(blob)
font = hb.Font(face)
font.set_variations({"wght": 800, "wdth": 100})
buf = hb.Buffer()
buf.add_str(text)
buf.guess_segment_properties()
hb.shape(font, buf, {"kern": True, "liga": True})

order = tt.getGlyphOrder()
glyphs = tt.getGlyphSet()
pen = SVGPathPen(glyphs)
cursor = 0.0
for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
    name = order[info.codepoint]
    ox = X + (cursor + pos.x_offset) * scale
    oy = Y - pos.y_offset * scale
    glyphs[name].draw(TransformPen(pen, (scale, 0, 0, -scale, ox, oy)))
    cursor += pos.x_advance + LS / scale
d = pen.getCommands()
# Round to 2 decimals to keep the file small.
import re
d = re.sub(r"-?\d+\.\d+", lambda m: f"{float(m.group()):.2f}".rstrip("0").rstrip("."), d)
print(d)
