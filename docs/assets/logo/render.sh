#!/usr/bin/env bash
# Renders the logo PNGs and favicon from corten-mark.svg, and the GitHub
# social preview from social-preview.svg plus the wordmark.
#
# Needs rsvg-convert and ImageMagick (magick), and the Archivo font
# (SIL Open Font License, https://fonts.google.com/specimen/Archivo) as two
# static TTF files. The font is passed by file because rsvg-convert on macOS
# picks fonts through CoreText and would silently substitute another one.
#
# Usage: docs/assets/logo/render.sh ARCHIVO_MEDIUM.ttf ARCHIVO_EXTRABOLD.ttf
set -euo pipefail
[ "$#" -eq 2 ] || { echo "usage: $0 ARCHIVO_MEDIUM.ttf ARCHIVO_EXTRABOLD.ttf" >&2; exit 2; }
medium=$1
bold=$2
for f in "$medium" "$bold"; do
    [ -f "$f" ] || { echo "no such font file: $f" >&2; exit 2; }
done
cd "$(dirname "$0")"

for size in 16 32 180 512; do
    rsvg-convert -w "$size" -h "$size" corten-mark.svg -o "corten-mark-$size.png"
done
magick corten-mark-16.png corten-mark-32.png favicon.ico

rsvg-convert -w 1280 -h 640 social-preview.svg -o social-preview.png
magick social-preview.png \
    -fill '#F6EBDD' -font "$bold" -pointsize 164 -kerning -4 -annotate +568+330 'corten' \
    -fill '#CDBFB4' -font "$medium" -pointsize 32 -kerning 0 \
    -annotate +576+408 'A hardened Rust profile that makes whole' \
    -annotate +576+452 'classes of security bugs impossible to write.' \
    social-preview.png
