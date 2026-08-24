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

- ✅ Оновлення bundled snapshots автоматизоване: `python scripts/update_snapshots.py` тягне Sherlock + WhatsMyName + Maigret (з портованим санитайзером) з upstream, валідує лоадерами, оновлює THIRD_PARTY_NOTICES. Стан: sherlock 206068d (контент без змін), wmn d434994 (715 entries), maigret 86593e7 (1906 rules); датасет загалом 2445 шаблонів / 24 POST.
- ✅ Розширення `ru_ua_sources` зроблено: категорії `public-registry` та `telegram-catalog`, плюс глобальні `legal-database`.

## Результати дослідження джерел (поточний раунд)

Метод: GitHub topic:osint top-by-stars + свіжі created:>2025 репозиторії + curated
списки cipher387/API-s-for-OSINT та jivoi/awesome-osint; усе пропущено через
політику проєкту.

### Кандидати P1 — keyless, нативні модулі

| Джерело | Напрямок | Що дає | Примітка |
|---|---|---|---|
| [ip-api.com](https://ip-api.com) | net/domain enrichment | Гео, ASN, org для IP; 45 req/min без ключа | Доповнює InternetDB (той дає порти/CVE, цей — гео/ASN) |
| [Kickbox open](https://open.kickbox.com) | email baseline | Deliverability/існування mailbox, 1 req/s без ключа | Той самий клас, що Gravatar: одиночна перевірка |
| [EVA pingutil](https://eva.pingutil.com) | email baseline | Валідність/диспозабельність email | Без ключа |
| [DomainsDB.info](https://domainsdb.info) | domain | Пошук зареєстрованих доменів за словом | Free API |
| [BotsArchive](https://botsarchive.com/docs.html) | telegram | JSON-каталог Telegram-ботів | Keyless |

### Кандидати P1 — curated source pack (без коду, тільки посилання)

✅ Додано цього раунду в `ru_ua_sources`: Telegago CSE, TG.World, Teleteg
(`telegram-catalog`) та CourtListener RECAP, ICIJ Offshore Leaks
(`legal-database`, глобальні pivots по особах/компаніях).

### Кандидати P2 — безкоштовний ключ оператора

| Джерело | Що дає | Примітка |
|---|---|---|
| CourtListener API | Повний пошук судових документів | Free key; розширення legal-database напряму |
| AlienVault OTX | Passive DNS, reputation для доменів/IP | Free key |
| SecurityTrails | Історичні DNS-записи | Free tier обмежений |

### Відхилено за політикою (зафіксовано, щоб не переглядати)

- **Breach-native пошук**: HIBP-клони — checkleaked.cc, osintcat.net, venacus.com,
  stealseek.io, leak-lookup, BreachDirectory, psbdmp.ws, haveibeenzuckered,
  iknowyour.dad. Закривається adapter-шаром h8mail/mosint.
- **Account-probing за телефоном/email**: epieos, castrickclues, predictasearch,
  whatsapp.checkleaked, telegram-finder, detectiva. Це пробів акаунтів — пряма
  заборона розділу «Границы безопасности».
- **Біометрія**: Face++ face search.
- **Paid SaaS агрегатори**: osint.industries, Social Links, Noimosiny, IntelX,
  Maltego hubs.
- **Сумнівна легальність**: GhostTrack (трекінг за номером), AVinfoBot/avtogram
  (VIN/платні авто-звіти RF) — сіра зона навіть як посилання.

## Наступний крок

З Пріоритету 1 лишились Overpass (гео-верифікація фото) — далі GLEIF/компанійний
напрямок і passive-DNS з безкоштовним ключем оператора.
