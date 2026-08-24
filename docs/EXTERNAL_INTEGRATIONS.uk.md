# Р—РѕРІРЅС–С€РЅС– С–РЅС‚РµРіСЂР°С†С–С—: РєР°РЅРґРёРґР°С‚Рё С‚Р° РїСЂС–РѕСЂРёС‚РµС‚Рё

РЎС‚Р°С‚СѓСЃ: РїР»Р°РЅ (backlog). РЈСЃРµ РЅРёР¶С‡Рµ вЂ” **С‚С–Р»СЊРєРё РїСѓР±Р»С–С‡РЅС– РґР¶РµСЂРµР»Р°**, СЃСѓРјС–СЃРЅС– Р·
РїРѕР»С–С‚РёРєРѕСЋ РїСЂРѕС”РєС‚Сѓ (`README.md в†’ Р“СЂР°РЅРёС†С‹ Р±РµР·РѕРїР°СЃРЅРѕСЃС‚Рё`): Р±РµР· РѕР±С…РѕРґСѓ РїСЂРёРІР°С‚РЅРѕСЃС‚С–,
Р±РµР· account-enumeration, Р±РµР· credential flows. РџРµСЂРµРґ РєРѕР¶РЅРёРј РїСѓРЅРєС‚РѕРј вЂ” С†С–Р»СЊРѕРІРёР№
РјРѕРґСѓР»СЊ СЂСѓС€С–СЏ Р№ С‚РёРї СЂРµР·СѓР»СЊС‚Р°С‚Сѓ.

## РџСЂС–РѕСЂРёС‚РµС‚ 1 вЂ” С€РІРёРґРєС– РїРµСЂРµРјРѕРіРё (Р±РµР· РєР»СЋС‡С–РІ)

| # | Р”Р¶РµСЂРµР»Рѕ | РљСѓРґРё РїСЂРёРєСЂСѓС‚РёС‚Рё | Р©Рѕ РґР°С” | Р—СѓСЃРёР»Р»СЏ |
|---|---|---|---|---|
| 1 | вњ… Р—Р РћР‘Р›Р•РќРћ: [Shodan InternetDB](https://internetdb.shodan.io) в†’ `modules/domain_intel.InternetDbModule` | domain live | Р’С–РґРєСЂРёС‚С– РїРѕСЂС‚Рё, hostnames, CVE-Р±Р°РіР°Р¶РЅРёРє IP. Р‘РµР· РєР»СЋС‡Р° | S |
| 2 | вњ… Р—Р РћР‘Р›Р•РќРћ: Wayback CDX в†’ `modules/domain_intel.WaybackCdxModule` | domain/url live | РџРµСЂС€РёР№ СЃРЅР°РїС€РѕС‚ = РЅРёР¶РЅСЏ РјРµР¶Р° РІС–РєСѓ РґРѕРјРµРЅСѓ; РѕСЃС‚Р°РЅРЅСЏ Р°СЂС…С–РІР°С†С–СЏ; observed_age_years | S |
| 3 | вњ… Р—Р РћР‘Р›Р•РќРћ: Mastodon `GET /api/v1/accounts/lookup` в†’ `modules/person_sources.MastodonLookupModule` | username live | Р’РµСЂРёС„С–РєРѕРІР°РЅС– display name, followers, created_at Р·Р°РјС–СЃС‚СЊ HTML-РіР°РґР°РЅСЊ | S |
| 4 | вњ… Р—Р РћР‘Р›Р•РќРћ: Bluesky AppView getProfile в†’ `modules/person_sources.BlueskyProfileModule` | username live | РЎСѓС‡Р°СЃРЅР° РїР»Р°С‚С„РѕСЂРјР°, РїСѓР±Р»С–С‡РЅРµ API Р±РµР· auth | S |
| 5 | вњ… Р—Р РћР‘Р›Р•РќРћ: GitHub REST users в†’ `modules/person_sources.GitHubUserModule` | username dossier (live) | name, bio, location, **public email**, created_at, repos/followers | S |
| 6 | вњ… Р—Р РћР‘Р›Р•РќРћ: Overpass API в†’ `exif_photo.overpass_nearby_features` | image live Р· EXIF GPS | Р†РјРµРЅРѕРІР°РЅС– OSM-РѕР±'С”РєС‚Рё РІ СЂР°РґС–СѓСЃС– 120 Рј вЂ” РІРµСЂРёС„С–РєР°С†С–СЏ РіРµРѕР»РѕРєР°С†С–С— С„РѕС‚Рѕ РїРѕ РјС–СЃС†РµРІРѕСЃС‚С– | M |
| 7 | вњ… Р—Р РћР‘Р›Р•РќРћ: Wikidata (wbsearchentities + wbgetentities) в†’ `modules/person_sources.WikidataPersonModule` | person pivot | Р”С–Р·Р°РјР±С–РіСѓР°С†С–СЏ РїСѓР±Р»С–С‡РЅРёС… РѕСЃС–Р±: aliases, СЂРѕРєРё Р¶РёС‚С‚СЏ, РѕРїРёСЃ. Findings = name-match only | M |

Р”РѕРґР°С‚РєРѕРІРѕ Р·СЂРѕР±Р»РµРЅРѕ:
- Gravatar-РїСЂРѕС„С–Р»СЊ Сѓ live email-РјРѕРґСѓР»С– (`gravatar-profile` source);
- Mastodon РѕСЃС‚Р°РЅРЅС– РїСѓР±Р»С–С‡РЅС– РїРѕСЃС‚Рё (`mastodon-posts`) С‚Р° Bluesky author feed (`bluesky-feed`)
  Сѓ live username-СЃРєР°РЅР°С…;
- urlScan.io search API в†’ `modules/domain_intel.UrlscanSearchModule` вЂ” РїСЂР°С†СЋС” С‚С–Р»СЊРєРё
  Р· РµРєСЃРїРѕСЂС‚РѕРІР°РЅРёРј `URLSCAN_API_KEY` РѕРїРµСЂР°С‚РѕСЂР°, Р±РµР· РєР»СЋС‡Р° С‡РµСЃРЅРёР№ `skipped`;
- UA/RF РїСѓР±Р»С–С‡РЅС– СЂРµС”СЃС‚СЂРё РІ ru-ua source pack (РєР°С‚РµРіРѕСЂС–СЏ `public-registry`):
  UA Court Register, data.gov.ua + EDR open dataset, RF EGRUL, Fedresurs;
- вњ… GLEIF API в†’ `modules/company_intel.GleifCompanyModule`: РЅРѕРІРёР№ target kind
  `company` (С–Рј'СЏ Р°Р±Рѕ LEI), РїСЂРѕС„С–Р»СЊ `company-safe` вЂ” РїРѕС‡Р°С‚РѕРє РєРѕРјРїР°РЅС–Р№РЅРѕРіРѕ РЅР°РїСЂСЏРјСѓ.

## РџСЂС–РѕСЂРёС‚РµС‚ 2 вЂ” Р±РµР·РєРѕС€С‚РѕРІРЅРёР№ РєР»СЋС‡ (operator РЅР°РґР°С” СЃР°Рј)

| 8 | вњ… Р—Р РћР‘Р›Р•РќРћ: urlScan.io search API в†’ `modules/domain_intel.UrlscanSearchModule` | url/domain live | Р†СЃС‚РѕСЂС–СЏ СЃРєР°РЅС–РІ/IP СЃС‚РѕСЂС–РЅРєРё | Free tier РґРѕСЃС‚Р°С‚РЅСЊРѕ; env `URLSCAN_API_KEY`, Р±РµР· РєР»СЋС‡Р° `skipped` |
| 9 | вњ… Р—Р РћР‘Р›Р•РќРћ: GLEIF API в†’ `modules/company_intel.GleifCompanyModule` | company | Р®СЂРѕСЃРѕР±Рё Р·Р° РЅР°Р·РІРѕСЋ/LEI, Р±РµР· РєР»СЋС‡Р° | РџРѕС‡Р°С‚РѕРє РєРѕРјРїР°РЅС–Р№РЅРѕРіРѕ РЅР°РїСЂСЏРјСѓ |
| 10 | вњ… Р—Р РћР‘Р›Р•РќРћ: UK Companies House в†’ `modules/company_intel.CompaniesHouseModule` | company live | Р РµС”СЃС‚СЂР°С†С–Р№РЅС– РґР°РЅС–, СЃС‚Р°С‚СѓСЃ, Р°РґСЂРµСЃР° | Free key `COMPANIES_HOUSE_API_KEY`; OpenCorporates РІС–РґС…РёР»РµРЅРѕ вЂ” С—С…РЅС–Р№ free API-РґРѕСЃС‚СѓРї Р·Р°РєСЂРёС‚РёР№ |
| 11 | вњ… Р—Р РћР‘Р›Р•РќРћ (keyless): passive hostnames в†’ `modules/domain_intel.PassiveDnsModule` (HackerTarget hostsearch) | domain live | РџР°СЃРёРІРЅС– РїС–РґРґРѕРјРµРЅРё + IP Р±РµР· РєР»СЋС‡Р° | Free tier Р· РґРµРЅРЅРёРј Р»С–РјС–С‚РѕРј; РІРёС‡РµСЂРїР°РЅРЅСЏ = С‡РµСЃРЅРёР№ `unknown` |

## РџСЂС–РѕСЂРёС‚РµС‚ 3 вЂ” РІРµР»РёРєС– upstream С‡РµСЂРµР· adapters

- `lanmaster53/recon-ng` вЂ” framework; adapter Сѓ СЃС‚РёР»С– SpiderFoot (isolated venv + JSON/CSV parse).
- `bellingcat/auto-archiver` вЂ” РІР¶Рµ РІ ROADMAP СЏРє С–РґРµСЏ; РїСЂРёСЂРѕРґРЅРёР№ adapter РґР»СЏ РјРµРґС–Р°-Р·Р°С†РµРїРѕРє.
- `Datalux/Osintgram`, `mxrch/GHunt` вЂ” **Р»РёС€Рµ restricted** (РїРѕС‚СЂРµР±СѓСЋС‚СЊ Р»РѕРіС–РЅ-СЃРµСЃС–С—); Р·Р° Р·СЂР°Р·РєРѕРј existing restricted-РјР°СЂРєСѓРІР°РЅРЅСЏ, Р±РµР· default execution.

## Р РµСЃСѓСЂСЃРё-РґР°С‚Р°СЃРµС‚Рё

- вњ… РћРЅРѕРІР»РµРЅРЅСЏ bundled snapshots Р°РІС‚РѕРјР°С‚РёР·РѕРІР°РЅРµ: `python scripts/update_snapshots.py` С‚СЏРіРЅРµ Sherlock + WhatsMyName + Maigret (Р· РїРѕСЂС‚РѕРІР°РЅРёРј СЃР°РЅРёС‚Р°Р№Р·РµСЂРѕРј) Р· upstream, РІР°Р»С–РґСѓС” Р»РѕР°РґРµСЂР°РјРё, РѕРЅРѕРІР»СЋС” THIRD_PARTY_NOTICES. РЎС‚Р°РЅ: sherlock 206068d (РєРѕРЅС‚РµРЅС‚ Р±РµР· Р·РјС–РЅ), wmn d434994 (715 entries), maigret 86593e7 (1906 rules); РґР°С‚Р°СЃРµС‚ Р·Р°РіР°Р»РѕРј 2445 С€Р°Р±Р»РѕРЅС–РІ / 24 POST.
- вњ… Р РѕР·С€РёСЂРµРЅРЅСЏ `ru_ua_sources` Р·СЂРѕР±Р»РµРЅРѕ: РєР°С‚РµРіРѕСЂС–С— `public-registry` С‚Р° `telegram-catalog`, РїР»СЋСЃ РіР»РѕР±Р°Р»СЊРЅС– `legal-database`.

## Р РµР·СѓР»СЊС‚Р°С‚Рё РґРѕСЃР»С–РґР¶РµРЅРЅСЏ РґР¶РµСЂРµР» (РїРѕС‚РѕС‡РЅРёР№ СЂР°СѓРЅРґ)

РњРµС‚РѕРґ: GitHub topic:osint top-by-stars + СЃРІС–Р¶С– created:>2025 СЂРµРїРѕР·РёС‚РѕСЂС–С— + curated
СЃРїРёСЃРєРё cipher387/API-s-for-OSINT С‚Р° jivoi/awesome-osint; СѓСЃРµ РїСЂРѕРїСѓС‰РµРЅРѕ С‡РµСЂРµР·
РїРѕР»С–С‚РёРєСѓ РїСЂРѕС”РєС‚Сѓ.

### P1 вЂ” вњ… Р—Р РћР‘Р›Р•РќРћ: СѓСЃС– С‡РѕС‚РёСЂРё keyless РєР°РЅРґРёРґР°С‚Рё СЂРµР°Р»С–Р·РѕРІР°РЅС–

- `modules/domain_intel.IpGeoModule` (`ip-api-geo`): РіРµРѕ/ASN/ISP/proxy/hosting РґР»СЏ СЂРµР·РѕР»РІР»РµРЅРѕРіРѕ IP;
- `modules/domain_intel.DomainsdbSearchModule` (`domainsdb-search`): Р·Р°СЂРµС”СЃС‚СЂРѕРІР°РЅС– РґРѕРјРµРЅРё Р·Р° СЃР»РѕРІРѕРј (brand/typo pivots), С‚Р°СЂРіРµС‚Рё domain+company;
- `modules/email_intel.EmailQualityModule` (`email-quality`): EVA deliverability/disposable/free + Kickbox disposable, РѕР±'С”РґРЅР°РЅРёР№ finding;
- `hackertarget-hostsearch` (passive DNS) вЂ” РґРёРІ. РІРёС‰Рµ.

РЈСЃС– РґРѕРґР°РЅС– РІ registry, Сѓ РїСЂРѕС„С–Р»С– `email-full`, `web-full`, `passive-recon`,
`safe`, `all-safe`; dry-run Р·Р° Р·Р°РјРѕРІС‡СѓРІР°РЅРЅСЏРј; РЅРµРІС–РґРѕРјС– РІС–РґРїРѕРІС–РґС– вЂ” С‡РµСЃРЅРёР№
`unknown`, РЅС–РєРѕР»Рё РЅРµ РІРёРіР°РґР°РЅРёР№ СЂРµР·СѓР»СЊС‚Р°С‚.

### РљР°РЅРґРёРґР°С‚Рё P1 вЂ” keyless, РЅР°С‚РёРІРЅС– РјРѕРґСѓР»С–

| Р”Р¶РµСЂРµР»Рѕ | РќР°РїСЂСЏРјРѕРє | Р©Рѕ РґР°С” | РџСЂРёРјС–С‚РєР° |
|---|---|---|---|
| ✅ [ip-api.com](https://ip-api.com) → IpGeoModule | net/domain enrichment | Р“РµРѕ, ASN, org РґР»СЏ IP; 45 req/min Р±РµР· РєР»СЋС‡Р° | Р”РѕРїРѕРІРЅСЋС” InternetDB (С‚РѕР№ РґР°С” РїРѕСЂС‚Рё/CVE, С†РµР№ вЂ” РіРµРѕ/ASN) |
| ✅ [Kickbox open](https://open.kickbox.com) → EmailQualityModule | email baseline | Deliverability/С–СЃРЅСѓРІР°РЅРЅСЏ mailbox, 1 req/s Р±РµР· РєР»СЋС‡Р° | РўРѕР№ СЃР°РјРёР№ РєР»Р°СЃ, С‰Рѕ Gravatar: РѕРґРёРЅРѕС‡РЅР° РїРµСЂРµРІС–СЂРєР° |
| ✅ [EVA pingutil](https://eva.pingutil.com) → EmailQualityModule | email baseline | Р’Р°Р»С–РґРЅС–СЃС‚СЊ/РґРёСЃРїРѕР·Р°Р±РµР»СЊРЅС–СЃС‚СЊ email | Р‘РµР· РєР»СЋС‡Р° |
| ✅ [DomainsDB.info](https://domainsdb.info) → DomainsdbSearchModule | domain/company | РџРѕС€СѓРє Р·Р°СЂРµС”СЃС‚СЂРѕРІР°РЅРёС… РґРѕРјРµРЅС–РІ Р·Р° СЃР»РѕРІРѕРј | Free API |
| [BotsArchive](https://botsarchive.com/docs.html) | telegram (backlog: JSON-каталог ботів) | JSON-РєР°С‚Р°Р»РѕРі Telegram-Р±РѕС‚С–РІ | Keyless |

### РљР°РЅРґРёРґР°С‚Рё P1 вЂ” curated source pack (Р±РµР· РєРѕРґСѓ, С‚С–Р»СЊРєРё РїРѕСЃРёР»Р°РЅРЅСЏ)

вњ… Р”РѕРґР°РЅРѕ С†СЊРѕРіРѕ СЂР°СѓРЅРґСѓ РІ `ru_ua_sources`: Telegago CSE, TG.World, Teleteg
(`telegram-catalog`) С‚Р° CourtListener RECAP, ICIJ Offshore Leaks
(`legal-database`, РіР»РѕР±Р°Р»СЊРЅС– pivots РїРѕ РѕСЃРѕР±Р°С…/РєРѕРјРїР°РЅС–СЏС…).

### РљР°РЅРґРёРґР°С‚Рё P2 вЂ” Р±РµР·РєРѕС€С‚РѕРІРЅРёР№ РєР»СЋС‡ РѕРїРµСЂР°С‚РѕСЂР°

| Р”Р¶РµСЂРµР»Рѕ | Р©Рѕ РґР°С” | РџСЂРёРјС–С‚РєР° |
|---|---|---|
| CourtListener API | РџРѕРІРЅРёР№ РїРѕС€СѓРє СЃСѓРґРѕРІРёС… РґРѕРєСѓРјРµРЅС‚С–РІ | Free key; СЂРѕР·С€РёСЂРµРЅРЅСЏ legal-database РЅР°РїСЂСЏРјСѓ |
| AlienVault OTX | Passive DNS, reputation РґР»СЏ РґРѕРјРµРЅС–РІ/IP | Free key |
| SecurityTrails | Р†СЃС‚РѕСЂРёС‡РЅС– DNS-Р·Р°РїРёСЃРё | Free tier РѕР±РјРµР¶РµРЅРёР№ |

### Р’С–РґС…РёР»РµРЅРѕ Р·Р° РїРѕР»С–С‚РёРєРѕСЋ (Р·Р°С„С–РєСЃРѕРІР°РЅРѕ, С‰РѕР± РЅРµ РїРµСЂРµРіР»СЏРґР°С‚Рё)

- **Breach-native РїРѕС€СѓРє**: HIBP-РєР»РѕРЅРё вЂ” checkleaked.cc, osintcat.net, venacus.com,
  stealseek.io, leak-lookup, BreachDirectory, psbdmp.ws, haveibeenzuckered,
  iknowyour.dad. Р—Р°РєСЂРёРІР°С”С‚СЊСЃСЏ adapter-С€Р°СЂРѕРј h8mail/mosint.
- **Account-probing Р·Р° С‚РµР»РµС„РѕРЅРѕРј/email**: epieos, castrickclues, predictasearch,
  whatsapp.checkleaked, telegram-finder, detectiva. Р¦Рµ РїСЂРѕР±С–РІ Р°РєР°СѓРЅС‚С–РІ вЂ” РїСЂСЏРјР°
  Р·Р°Р±РѕСЂРѕРЅР° СЂРѕР·РґС–Р»Сѓ В«Р“СЂР°РЅРёС†С‹ Р±РµР·РѕРїР°СЃРЅРѕСЃС‚РёВ».
- **Р‘С–РѕРјРµС‚СЂС–СЏ**: Face++ face search.
- **Paid SaaS Р°РіСЂРµРіР°С‚РѕСЂРё**: osint.industries, Social Links, Noimosiny, IntelX,
  Maltego hubs.
- **РЎСѓРјРЅС–РІРЅР° Р»РµРіР°Р»СЊРЅС–СЃС‚СЊ**: GhostTrack (С‚СЂРµРєС–РЅРі Р·Р° РЅРѕРјРµСЂРѕРј), AVinfoBot/avtogram
  (VIN/РїР»Р°С‚РЅС– Р°РІС‚Рѕ-Р·РІС–С‚Рё RF) вЂ” СЃС–СЂР° Р·РѕРЅР° РЅР°РІС–С‚СЊ СЏРє РїРѕСЃРёР»Р°РЅРЅСЏ.

## РќР°СЃС‚СѓРїРЅРёР№ РєСЂРѕРє

Р— РџСЂС–РѕСЂРёС‚РµС‚Сѓ 1 Р»РёС€РёР»РёСЃСЊ Overpass (РіРµРѕ-РІРµСЂРёС„С–РєР°С†С–СЏ С„РѕС‚Рѕ) вЂ” РґР°Р»С– GLEIF/РєРѕРјРїР°РЅС–Р№РЅРёР№
РЅР°РїСЂСЏРјРѕРє С– passive-DNS Р· Р±РµР·РєРѕС€С‚РѕРІРЅРёРј РєР»СЋС‡РµРј РѕРїРµСЂР°С‚РѕСЂР°.
