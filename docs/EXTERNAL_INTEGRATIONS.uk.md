# Зовнішні інтеграції: кандидати та пріоритети

Статус: план (backlog). Усе нижче — **тільки публічні джерела**, сумісні з
політикою проєкту (`README.md → Границы безопасности`): без обходу приватності,
без account-enumeration, без credential flows. Перед кожним пунктом — цільовий
модуль рушія й тип результату.

## Пріоритет 1 — швидкі перемоги (без ключів)

| # | Джерело | Куди прикрутити | Що дає | Зусилля |
|---|---|---|---|---|
| 1 | ✅ ЗРОБЛЕНО: [Shodan InternetDB](https://internetdb.shodan.io) → `modules/domain_intel.InternetDbModule` | domain live | Відкриті порти, hostnames, CVE-багажник IP. Без ключа | S |
| 2 | ✅ ЗРОБЛЕНО: Wayback CDX → `modules/domain_intel.WaybackCdxModule` | domain/url live | Перший снапшот = нижня межа віку домену; остання архівація; observed_age_years | S |
| 3 | ✅ ЗРОБЛЕНО: Mastodon `GET /api/v1/accounts/lookup` → `modules/person_sources.MastodonLookupModule` | username live | Верифіковані display name, followers, created_at замість HTML-гадань | S |
| 4 | ✅ ЗРОБЛЕНО: Bluesky AppView getProfile → `modules/person_sources.BlueskyProfileModule` | username live | Сучасна платформа, публічне API без auth | S |
| 5 | ✅ ЗРОБЛЕНО: GitHub REST users → `modules/person_sources.GitHubUserModule` | username dossier (live) | name, bio, location, **public email**, created_at, repos/followers | S |
| 6 | ✅ ЗРОБЛЕНО: Overpass API → `exif_photo.overpass_nearby_features` | image live з EXIF GPS | Іменовані OSM-об'єкти в радіусі 120 м — верифікація геолокації фото по місцевості | M |
| 7 | ✅ ЗРОБЛЕНО: Wikidata (wbsearchentities + wbgetentities) → `modules/person_sources.WikidataPersonModule` | person pivot | Дізамбігуація публічних осіб: aliases, роки життя, опис. Findings = name-match only | M |

Додатково зроблено:
- Gravatar-профіль у live email-модулі (`gravatar-profile` source);
- Mastodon останні публічні пости (`mastodon-posts`) та Bluesky author feed (`bluesky-feed`)
  у live username-сканах;
- urlScan.io search API → `modules/domain_intel.UrlscanSearchModule` — працює тільки
  з експортованим `URLSCAN_API_KEY` оператора, без ключа чесний `skipped`;
- UA/RF публічні реєстри в ru-ua source pack (категорія `public-registry`):
  UA Court Register, data.gov.ua + EDR open dataset, RF EGRUL, Fedresurs;
- ✅ GLEIF API → `modules/company_intel.GleifCompanyModule`: новий target kind
  `company` (ім'я або LEI), профіль `company-safe` — початок компанійного напряму.

## Пріоритет 2 — безкоштовний ключ (operator надає сам)

| 8 | ✅ ЗРОБЛЕНО: urlScan.io search API → `modules/domain_intel.UrlscanSearchModule` | url/domain live | Історія сканів/IP сторінки | Free tier достатньо; env `URLSCAN_API_KEY`, без ключа `skipped` |
| 9 | ✅ ЗРОБЛЕНО: GLEIF API → `modules/company_intel.GleifCompanyModule` | company | Юрособи за назвою/LEI, без ключа | Початок компанійного напряму |
| 10 | ✅ ЗРОБЛЕНО: UK Companies House → `modules/company_intel.CompaniesHouseModule` | company live | Реєстраційні дані, статус, адреса | Free key `COMPANIES_HOUSE_API_KEY`; OpenCorporates відхилено — їхній free API-доступ закритий |
| 11 | ✅ ЗРОБЛЕНО (keyless): passive hostnames → `modules/domain_intel.PassiveDnsModule` (HackerTarget hostsearch) | domain live | Пасивні піддомени + IP без ключа | Free tier з денним лімітом; вичерпання = чесний `unknown` |

## Пріоритет 3 — великі upstream через adapters

- `lanmaster53/recon-ng` — framework; adapter у стилі SpiderFoot (isolated venv + JSON/CSV parse).
- `bellingcat/auto-archiver` — вже в ROADMAP як ідея; природний adapter для медіа-зацепок.
- `Datalux/Osintgram`, `mxrch/GHunt` — **лише restricted** (потребують логін-сесії); за зразком existing restricted-маркування, без default execution.

## Ресурси-датасети

- ✅ Оновлення bundled snapshots автоматизоване: `python scripts/update_snapshots.py` тягне Sherlock + WhatsMyName з upstream, валідує лоадерами, оновлює THIRD_PARTY_NOTICES (поточні коміти: sherlock 206068d [без змін контенту], wmn d434994). Maigret потребує порту санитайзера projection у репо — окрема задача.
- Розширення `ru_ua_sources`: публічні реєстри UA (`data.gov.ua`, `reyestr.court.gov.ua`) та RF-джерела з поточної розмітки top-100 — як curated source pack, не як скрапери.

## Що НЕ інтегрувати (свідомо)

- HIBP/breach-lookup у native-коді — закривається adapters `h8mail`/`mosint` з явним `--execute`.
- Будь-які API, що вимагають логін-сесію соцмережі, скрейпинг за логіном, обходи rate-limit.
- Платні агрегатори (Maltego transform hubs тощо) — поза scope локального інструмента.

## Наступний крок

З Пріоритету 1 лишились Overpass (гео-верифікація фото) — далі GLEIF/компанійний
напрямок і passive-DNS з безкоштовним ключем оператора.
