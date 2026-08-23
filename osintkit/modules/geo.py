"""Geolocation utilities for imagery verification.

* Shadow-based time estimation: given photo coords, shadow azimuth and the
  ratio shadow-length / object-height, compute candidate capture times (UTC).
* Map link builders (Google/Yandex/OSM/Mapillary/SunCalc) for quick manual checks.
* Nominatim reverse geocoding.
"""
from __future__ import annotations

import datetime as dt
import math
import urllib.parse

from osintkit.core import Finding, HttpClient
from osintkit.modules.base import Module, register


def _sun_position(lat: float, lon: float, when: dt.datetime) -> tuple[float, float]:
    """NOAA-approximation solar position -> (azimuth_deg, altitude_deg)."""
    jd = when.timestamp() / 86400.0 + 2440587.5
    n = jd - 2451545.0
    L = math.radians((280.460 + 0.9856474 * n) % 360)
    g = math.radians((357.528 + 0.9856003 * n) % 360)
    lam = L + math.radians(1.915) * math.sin(g) + math.radians(0.02) * math.sin(2 * g)
    eps = math.radians(23.439 - 0.0000004 * n)
    dec = math.asin(math.sin(eps) * math.sin(lam))
    ra = math.atan2(math.cos(eps) * math.sin(lam), math.cos(lam))
    gmst = (18.697374558 + 24.06570982441908 * n) % 24
    lst = math.radians(((gmst * 15 + lon) % 360))
    ha = lst - ra
    lat_r = math.radians(lat)
    alt = math.asin(math.sin(lat_r) * math.sin(dec) + math.cos(lat_r) * math.cos(dec) * math.cos(ha))
    az = math.atan2(-math.sin(ha), math.tan(dec) * math.cos(lat_r) - math.sin(lat_r) * math.cos(ha))
    return math.degrees(az) % 360, math.degrees(alt)


@register
class GeoModule(Module):
    name = "geo"
    help = ("Geo utils: 'lat,lon;azimuth;height_ratio' for shadow time estimate, "
            "or 'lat,lon' for map links + reverse geocode")
    target_hint = "'50.4501,30.5234' or '50.45,30.52;180;2.5'"

    async def run(self, target: str, http: HttpClient) -> list[Finding]:
        parts = [p.strip() for p in target.split(";")]
        lat_s, lon_s = parts[0].split(",")
        lat, lon = float(lat_s), float(lon_s)
        findings: list[Finding] = []

        q = urllib.parse.quote(f"{lat},{lon}")
        findings.append(Finding(kind="geo", source=self.name,
                                value=f"{lat:.5f},{lon:.5f}", confidence="high",
                                extra={
                                    "google": f"https://www.google.com/maps/@{lat},{lon},17z",
                                    "yandex": f"https://yandex.ru/maps/?ll={lon}%2C{lat}&z=17",
                                    "osm": f"https://www.openstreetmap.org/#map=17/{lat}/{lon}",
                                    "mapillary": f"https://www.mapillary.com/app/?lat={lat}&lng={lon}&z=17",
                                    "suncalc": f"https://www.suncalc.org/#/{lat},{lon},15/",
                                }))

        # Reverse geocode (Nominatim — requires polite usage)
        try:
            nom = await http.get_json(
                f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}"
                f"&format=jsonv2&accept-language=ru,en")
            findings.append(Finding(kind="place", source=self.name,
                                    value=nom.get("display_name", "?"),
                                    confidence="medium"))
        except Exception:
            pass

        if len(parts) == 3:
            azimuth = float(parts[1])
            ratio = float(parts[2])   # shadow length / object height
            # tan(alt) = height/shadow_len => alt = atan(1/ratio)
            needed_alt = math.degrees(math.atan(1.0 / ratio))
            matches: list[str] = []
            base = dt.datetime.now(dt.timezone.utc).replace(
                hour=12, minute=0, second=0, microsecond=0)
            day = base
            from datetime import timedelta
            for d in range(0, 365, 10):     # sample through a year
                t = day - timedelta(days=d)
                for h in range(5, 20):
                    when = t.replace(hour=h)
                    try:
                        az, alt = _sun_position(lat, lon, when)
                    except ValueError:
                        continue
                    if abs(alt - needed_alt) < 1.5 and abs(az - azimuth) < 6:
                        matches.append(when.strftime("%Y-%m-%d ~%H:00 UTC"))
            findings.append(Finding(
                kind="shadowtime", source=self.name,
                value=(f"Shadow az={azimuth}°, ratio={ratio} → sun alt ≈ {needed_alt:.1f}°; "
                       f"candidate times: " + "; ".join(matches[:12]))
                      if matches else
                      f"No candidates found in sampled year for az={azimuth}°, ratio={ratio}",
                confidence="low" if matches else "medium"))
        return findings
