# Зовнішні інтеграції: кандидати та пріоритети

Статус: план (backlog). Усе нижче — **тільки публічні джерела**, сумісні з
політикою проєкту (`README.md → Границы безопасности`): без обходу приватності,
без account-enumeration, без credential flows. Перед кожним пунктом — цільовий
модуль рушія й тип результату.

## Пріоритет 1 — швидкі перемоги (без ключів)

| # | Джерело | Куди прикрутити | Що дає | Зусилля |
|---|---|---|---|---|
| 1 | [Shodan InternetDB](https://internetdb.shodan.io) `GET /<ip>` | `modules/net` + derived IP з domain scan | Відкриті порти, hostnames, CVE-багажник IP. Без ключа, ліміти щедрі | S |
| 2 | Wayback CDX `web.archive.org/cdx/search/cdx?url=<domain>&output=json&limit=-5` | domain/url модуль + `osintkit/modules/web_archive` | Перший снапшот = нижня межа віку домену; кількість збережень; остання архівація | S |
| 3 | ✅ ЗРОБЛЕНО: Mastodon `GET /api/v1/accounts/lookup` → `modules/person_sources.MastodonLookupModule` | username live | Верифіковані display name, followers, created_at замість HTML-гадань | S |
| 4 | ✅ ЗРОБЛЕНО: Bluesky AppView getProfile → `modules/person_sources.BlueskyProfileModule` | username live | Сучасна платформа, публічне API без auth | S |
| 5 | ✅ ЗРОБЛЕНО: GitHub REST users → `modules/person_sources.GitHubUserModule` | username dossier (live) | name, bio, location, **public email**, created_at, repos/followers | S |
| 6 | Overpass API (OpenStreetMap) | `exif_photo`/geo-напрямок | «Що поруч із координатами»: будинки, вежі, дороги — верифікація геолокації фото | M |
| 7 | ✅ ЗРОБЛЕНО: Wikidata (wbsearchentities + wbgetentities) → `modules/person_sources.WikidataPersonModule` | person pivot | Дізамбігуація публічних осіб: aliases, роки життя, опис. Findings = name-match only | M |

Додатково зроблено: Gravatar-профіль у live email-модулі (`gravatar-profile` source) —
публічні self-published дані, прив'язані до хешу адреси.

## Пріоритет 2 — безкоштовний ключ (operator надає сам)

| # | Джерело | Куди | Що дає | Примітка |
|---|---|---|---|---|
| 8 | urlScan.io API | url/domain профілі | Історія скріншотів/IP сторінки, схожі сайти | Free tier достатньо; env `URLSCAN_API_KEY` |
| 9 | GLEIF API | новий напрямок company | Юрособи за назвою/LEI; без ключа базовий пошук | Почати з нього, компанійний напряму поки немає взагалі |
| 10 | Companies House (UK) / OpenCorporates | company напрямок | Реєстраційні дані, директора | Key required; OpenCorporates free tier обмежений |
| 11 | SecurityTrails / PassiveDNS free tier | domain-recon adapter-профіль | Пасивний DNS, історичні A-записи | Ключ оператора; не в default profiles |

## Пріоритет 3 — великі upstream через adapters

- `lanmaster53/recon-ng` — framework; adapter у стилі SpiderFoot (isolated venv + JSON/CSV parse).
- `bellingcat/auto-archiver` — вже в ROADMAP як ідея; природний adapter для медіа-зацепок.
- `Datalux/Osintgram`, `mxrch/GHunt` — **лише restricted** (потребують логін-сесії); за зразком existing restricted-маркування, без default execution.

## Ресурси-датасети

- Періодичне оновлення bundled snapshots Sherlock/WMN/Maigret (зараз зафіксовані commit'и) + `tools doctor`-подібна перевірка свіжості.
- Розширення `ru_ua_sources`: публічні реєстри UA (`data.gov.ua`, `reyestr.court.gov.ua`) та RF-джерела з поточної розмітки top-100 — як curated source pack, не як скрапери.

## Що НЕ інтегрувати (свідомо)

- HIBP/breach-lookup у native-коді — закривається adapters `h8mail`/`mosint` з явним `--execute`.
- Будь-які API, що вимагають логін-сесію соцмережі, скрейпинг за логіном, обходи rate-limit.
- Платні агрегатори (Maltego transform hubs тощо) — поза scope локального інструмента.

## Рекомендований перший крок

Пункти 1–2 (InternetDB + Wayback CDX): ~150 рядків разом із тестами,
закривають найчастіші питання «що це за сервер» і «скільки цьому домену років»
без жодних ключів.
