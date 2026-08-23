"""EXIF photo forensics for image URLs (sync bridge).

If the photo still carries EXIF GPS you get exact coordinates plus map
links — historically the most fruitful artifact in conflict-photo checks.
A stripped-EXIF result is reported as information too.
"""
from __future__ import annotations

import io

import httpx
from PIL import Image
from PIL.ExifTags import IFD

from ..engine import Finding, RunConfig, ScanTarget


def _dms_to_deg(dms, ref: str) -> float:
    deg = float(dms[0]) + float(dms[1]) / 60 + float(dms[2]) / 3600
    return -deg if ref.strip() in ("S", "W") else deg


class ExifPhotoModule:
    name = "exif"
    supported_targets = ("url",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        url = target.value
        low = url.lower().split("?")[0]
        if not low.endswith((".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff")):
            return (Finding(module=self.name, source="pillow", target=url,
                            status="not_found", confidence="low",
                            evidence="URL does not look like an image"),)
        try:
            resp = httpx.get(url, timeout=config.timeout,
                             headers={"User-Agent": config.user_agent},
                             follow_redirects=True)
            resp.raise_for_status()
            img = Image.open(io.BytesIO(resp.content))
        except Exception as exc:  # noqa: BLE001
            return (Finding(module=self.name, source="pillow", target=url,
                            status="skipped", confidence="low",
                            evidence=f"fetch/decode failed: {exc}"),)

        findings: list[Finding] = [
            Finding(module=self.name, source="pillow", target=url,
                    status="hit", title=f"{img.format} {img.size[0]}x{img.size[1]}",
                    confidence="high")]

        exif = img.getexif()
        gps_ifd = exif.get_ifd(IFD.GPSInfo)
        exif_ifd = exif.get_ifd(IFD.Exif)
        make = str(exif.get(271, "")).strip()
        model = str(exif.get(272, "")).strip()
        taken = str(exif_ifd.get(36867, "") or exif.get(306, "")).strip()
        software = str(exif.get(305, "")).strip()

        camera = " ".join(b for b in (make, model) if b and b.lower() != "none")
        meta_bits = [b for b in (camera, taken, software) if b]
        if meta_bits:
            findings.append(Finding(
                module=self.name, source="pillow", target=url, status="hit",
                title=" · ".join(meta_bits), confidence="high",
                metadata={
                    **({"camera": camera} if camera else {}),
                    **({"taken_date": taken} if taken else {}),
                    **({"software": software[:60]} if software else {}),
                }))

        if gps_ifd and 2 in gps_ifd and 4 in gps_ifd:
            try:
                lat = _dms_to_deg(gps_ifd[2], str(gps_ifd.get(1, "N")))
                lon = _dms_to_deg(gps_ifd[4], str(gps_ifd.get(3, "E")))
                q = f"{lat:.6f},{lon:.6f}"
                findings.append(Finding(
                    module=self.name, source="exif-gps", target=url,
                    status="hit", confidence="high",
                    title="EXIF GPS: " + q,
                    url=("https://www.openstreetmap.org/?mlat=" + str(lat)
                         + "&mlon=" + str(lon) + "#map=16/" + q),
                    metadata={
                        # recognized by entities_from_findings -> graph node
                        "coordinates": q,
                        "google_maps": "https://maps.google.com/?q=" + q,
                        "yandex_maps": ("https://yandex.ru/maps/?ll="
                                        + str(lon) + "%2C" + str(lat) + "&z=16"),
                    }))
            except Exception as exc:  # noqa: BLE001
                findings.append(Finding(
                    module=self.name, source="exif-gps", target=url,
                    status="skipped", confidence="low",
                    evidence=f"GPS present but unparsable: {exc}"))
        else:
            findings.append(Finding(
                module=self.name, source="exif-gps", target=url,
                status="not_found", confidence="medium",
                evidence="No EXIF GPS (stripped or location off)"))
        return tuple(findings)
