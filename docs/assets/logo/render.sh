#!/usr/bin/env bash
# Renders the logo PNGs and favicon from corten-mark.svg, and the GitHub
# social preview from social-preview.svg.
#
# Needs rsvg-convert, ImageMagick (magick) and the Archivo font installed
# (SIL Open Font License, https://fonts.google.com/specimen/Archivo; the
# variable font covers both weights used). A renderer that cannot find a
# font substitutes another without a word, so the script first renders the
# word in "Archivo" and in a family that does not exist, and stops if the
# two come out the same.
#
# Usage: docs/assets/logo/render.sh
set -euo pipefail
cd "$(dirname "$0")"

probe=$(mktemp -d)
trap 'rm -rf "$probe"' EXIT
for family in Archivo No-Such-Font-Corten; do
    printf '<svg xmlns="http://www.w3.org/2000/svg" width="600" height="200"><text x="10" y="150" font-family="%s" font-weight="800" font-size="140">corten</text></svg>' \
        "$family" > "$probe/$family.svg"
    rsvg-convert "$probe/$family.svg" -o "$probe/$family.png"
done
# compare -metric AE prints the number of differing pixels on stderr and
# exits 1 when they differ, which is the case wanted here.
differing=$(magick compare -metric AE "$probe/Archivo.png" "$probe/No-Such-Font-Corten.png" null: 2>&1 || true)
if [ "${differing%% *}" = "0" ]; then
    echo "render.sh: Archivo is not installed (it renders like a missing font); install it first" >&2
    exit 1
fi

for size in 16 32 180 512; do
    rsvg-convert -w "$size" -h "$size" corten-mark.svg -o "corten-mark-$size.png"
done
magick corten-mark-16.png corten-mark-32.png favicon.ico
rsvg-convert -w 1280 -h 640 social-preview.svg -o social-preview.png
echo "render.sh: rendered (Archivo check: ${differing%% *} pixels differ from a missing font)"
