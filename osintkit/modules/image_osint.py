"""Image forensics: EXIF extraction + reverse-image search pivots.

Target may be a local file path or an http(s) image URL. If the photo still
carries EXIF GPS you get exact coordinates and map links — historically the
most fruitful artifact in conflict-photo verification. A stripped-EXIF result
is reported too (that is information as well).
"""
from __future__ import annotations

import io
import pathlib
import urllib.parse

from osintkit.core import Finding, HttpClient
from osintkit.modules.base import Module, register


def _dms_to_deg(dms, ref: str) -> float:
    deg = float(dms[0]) + float(dms[1]) / 60 + float(dms[2]) / 3600
    return -deg if ref.strip() in ("S", "W") else deg


@register
class ImageModule(Module):
    name = "image"
    help = "Photo EXIF (GPS!, camera, date) + reverse search pivots"
    target_hint = "local path or image URL"

    _IMG_EXTS = (".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".bmp")

    def accepts(self, target: str) -> bool:
        import pathlib
        low = target.lower().split("?")[0]
        if low.startswith("http"):
            return low.endswith(self._IMG_EXTS)
        p = pathlib.Path(target)
        return p.is_file() and low.endswith(self._IMG_EXTS)

    async def run(self, target: str, http: HttpClient) -> list[Finding]:
        data = None
        src = target
        if target.lower().startswith(("http://", "https://")):
            resp = await http._client.get(target, headers=http.headers())
            data = resp.content
            src = target.split("?")[0].rstrip("/")
        else:
            p = pathlib.Path(target)
            if not p.exists():
                raise FileNotFoundError(target)
            data = p.read_bytes()

        from PIL import Image
        from PIL.ExifTags import IFD
        img = Image.open(io.BytesIO(data))
        findings: list[Finding] = [
            Finding(kind="photo", source=self.name,
                    value=f"{img.format} {img.size[0]}x{img.size[1]}",
                    confidence="high")]

        exif = img.getexif()
        gps_ifd = exif.get_ifd(IFD.GPSInfo)
        exif_ifd = exif.get_ifd(IFD.Exif)

        make = str(exif.get(271, "")).strip()
        model = str(exif.get(272, "")).strip()
        software = str(exif.get(305, "")).strip()
        taken = str(exif_ifd.get(36867, "") or exif.get(306, "")).strip()

        if gps_ifd:
            try:
                lat = _dms_to_deg(gps_ifd[2], str(gps_ifd.get(1, "N")))
                lon = _dms_to_deg(gps_ifd[4], str(gps_ifd.get(3, "E")))
                q = f"{lat:.6f},{lon:.6f}"
                findings.append(Finding(
                    kind="geo", source=self.name,
                    value=f"EXIF GPS: {q}", confidence="high",
                    url=("https://www.openstreetmap.org/?mlat=" + str(lat) +
                         "&mlon=" + str(lon) + "#map=16/" + q),
                    extra={
                        "google_maps": "https://maps.google.com/?q=" + q,
                        "yandex_maps": "https://yandex.ru/maps/?ll=" +
                                        str(lon) + "%2C" + str(lat) + "&z=16",
                    }))
            except Exception as exc:
                findings.append(Finding(kind="geo", source=self.name,
                                        value="GPS present but unparsable: "
                                              + str(exc), confidence="low"))
        else:
            findings.append(Finding(
                kind="photo", source=self.name,
                value="No EXIF GPS (stripped or location off) — "
                      "use reverse search below", confidence="medium"))

        cam_bits = [b for b in (make, model) if b and b.lower() != "none"]
        meta_extra: dict = {}
        if cam_bits:
            meta_extra["camera"] = " ".join(cam_bits)
        if software and software.lower() != "none":
            meta_extra["software"] = software[:60]
        if taken:
            meta_extra["taken"] = taken
        if meta_extra:
            summary = " · ".join(v for v in (meta_extra.get("camera"),
                                             meta_extra.get("taken"),
                                             meta_extra.get("software")) if v)
            findings.append(Finding(kind="photo", source=self.name,
                                    value=summary, confidence="high",
                                    extra=meta_extra))

        if src.lower().startswith("http"):
            u = urllib.parse.quote(src, safe="")
            findings.append(Finding(
                kind="reverse_search", source=self.name,
                value="Reverse image search pivots", confidence="low",
                url="https://lens.google.com/uploadbyurl?url=" + u,
                extra={
                    "yandex_images":
                        "https://yandex.com/images/search?rpt=imageview&url="
                        + u,
                    "tineye": "https://tineye.com/search?url=" + u,
                    "bing_visual":
                        "https://www.bing.com/images/search?view=detailv2"
                        "&iss=sbi&q=imgurl:" + u,
                }))
        else:
            findings.append(Finding(
                kind="lead", source=self.name,
                value="For reverse search use Yandex Images / Google Lens "
                      "upload manually with this file",
                confidence="low"))
        return findings
