# Corten logo

A weathering-steel plate with a C cut through it, centred on a layered rust shield. Corten is weathering steel: the rust layer that forms on it is what protects the metal, which is the project's idea in one picture. The layers echo the five enforcement layers (spec section 10).

The mark is original. It is not derived from the Rust logo: the Rust Foundation's trademark policy requires written permission to use the Rust marks within another trademark.

| File | Use |
| --- | --- |
| `corten-mark.svg` | The mark; scales to any size |
| `corten-mark-16.png`, `-32.png`, `-180.png`, `-512.png` | Raster sizes (favicon, touch icon, avatars) |
| `favicon.ico` | 16 and 32 px |
| `social-preview.svg`, `social-preview.png` | GitHub social preview, 1280×640. Upload the PNG in the repository's Settings, Social preview: GitHub has no API for it |
| `render.sh` | Regenerates every PNG and the favicon |

Palette, outer shield to core: `#B5541E`, `#8B3A1A`, `#6E2A12`, `#3A160A`; plate gradient `#F0A060` → `#D2702A` → `#A9481B`. Wordmark: Archivo ExtraBold, lower case; tagline Archivo Medium. Archivo is under the SIL Open Font License and must be installed to render; `render.sh` takes no arguments and stops if the text would render in a substitute font (it compares Archivo with a family that does not exist).
