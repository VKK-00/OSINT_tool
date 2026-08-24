# Зовнішні інтеграції: кандидати та пріоритети

Статус: живий план. Усе нижче — публічні джерела, сумісні з політикою
проєкту (`README.md → Границы безопасности`); винятки явно позначені.

## Реалізовано (хронологія)

| Джерело | Модуль | Напрямок | Ключ |
|---|---|---|---|
| Mastodon accounts/lookup + statuses | `person_sources.MastodonLookupModule` | username live | — |
| Bluesky AppView getProfile + author feed | `person_sources.BlueskyProfileModule` | username live | — |
| GitHub REST users | `person_sources.GitHubUserModule` | username live | — |
| Wikidata (search + entities) | `person_sources.WikidataPersonModule` | person pivot | — |
| Gravatar profile | `email.EmailScanModule` (`gravatar-profile`) | email live | — |
| Shodan InternetDB | `domain_intel.InternetDbModule` | domain live | — |
| Wayback CDX | `domain_intel.WaybackCdxModule` | domain/url live | — |
| urlScan.io search | `domain_intel.UrlscanSearchModule` | domain/url live | `URLSCAN_API_KEY` |
| HackerTarget hostsearch (passive DNS) | `domain_intel.PassiveDnsModule` | domain live | — |
| ip-api.com geo/ASN | `domain_intel.IpGeoModule` | domain/url live | — |
| DomainsDB.info search | `domain_intel.DomainsdbSearchModule` | domain/company live | — |
| EVA + Kickbox email quality | `email_intel.EmailQualityModule` | email live | — |
| GLEIF entities | `company_intel.GleifCompanyModule` | company live | — |
| UK Companies House | `company_intel.CompaniesHouseModule` | company live | `COMPANIES_HOUSE_API_KEY` |
| HIBP breach metadata | `breach_intel.HibpBreachModule` | email live | `HIBP_API_KEY` |
| psbdmp.ws dump references | `breach_intel.PsbdmpDumpModule` | email/phone/username/domain live | — |
| Overpass API (OSM nearby) | `exif_photo.overpass_nearby_features` | image з EXIF GPS | — |
| CourtListener search v4 | `legal_intel.CourtListenerModule` | company/person live (RECAP+opinions) | `COURTLISTENER_API_KEY` |
| AlienVault OTX passive DNS | `domain_intel.OtxPassiveDnsModule` | domain live | `OTX_API_KEY` |
| recon-ng headless run | adapter `lanmaster53/recon-ng` | domain live | env RECONNG_* (operator .rc script) |
| Bellingcat auto-archiver | adapter `bellingcat/auto-archiver` | url archive | env AUTOARCHIVER_CONFIG |

## Результати дослідження джерел (раунд 2026)

Метод: GitHub topic:osint top-by-stars + created:>2025 + curated списки
cipher387/API-s-for-OSINT та jivoi/awesome-osint, пропущені через політику.

### Що вже додано як curated source pack

- `telegram-catalog`: Telegago (Google CSE по t.me), TG.World, Teleteg;
- `legal-database`: CourtListener RECAP (дзеркало PACER), ICIJ Offshore Leaks —
  глобальні pivots по особах і компаніях.

### Кандидати в черзі

| Джерело | Напрямок | Примітка |
|---|---|---|
| BotsArchive JSON | telegram | каталог ботів; уточнити ендпоінт |
| SecurityTrails | історичні DNS | free tier обмежений |

## Політика: рішення оператора (2026)

### Account-probing за телефоном/email — дозволено у restricted-класі ✅

`megadose/holehe` (email → ~150 сайтів) та `megadose/ignorant` (телефон →
соцплатформи) — повноцінні restricted-адаптери: команди, парсери `[+] Site`
виводу, readiness. Доступні **лише** через `--include-restricted` /
`run-adapter --allow-restricted --execute`, один таргет за запуск.
SaaS-обгортки над тим самим (epieos, castrickclues, predictasearch,
whatsapp.checkleaked, telegram-finder, detectiva) не інтегруються: закриті
сервіси без публічного API — скрейпинг не робимо, OSS-еквіваленти вбудовані.

### Breach-metadata — реалізовано у межах лінії ✅

`hibp-breaches` (офіційний HIBP API за ключем): назви витоків, дати, класи
даних; паролі API не повертає за дизайном. `psbdmp-dumps`: безключовий
psbdmp.ws, тільки ID/посилання на дампи — вміст оглядає оператор вручну.
Обидва — у `deep-full` поруч із deep-leaks; у safe/all-safe їх немає.

**Лінія, яка лишається:** сирі паролі/credential-dumps не потрапляють у звіти;
масовий режим відсутній; один таргет за запуск.

### Відхилено свідомо

- ❌ SaaS-клони без офіційного API (checkleaked.cc, osintcat.net, venacus.com,
  stealseek.io, leak-lookup, BreachDirectory, haveibeenzuckered,
  iknowyour.dad) — реверс-інжиніринг приватних ендпоінтів; еквівалент закривають
  h8mail/mosint адаптери + hibp-breaches вище.
- ❌ Біометрія: Face++ face search.
- ❌ Paid SaaS агрегатори: osint.industries, Social Links, Noimosiny, IntelX,
  Maltego hubs.
- ❌ Сумнівна легальність: GhostTrack, AVinfoBot/avtogram (платні VIN-звіти).
- ❌ Великі upstream через adapters (у черзі, не відхилені): recon-ng,
  bellingcat/auto-archiver; Osintgram/GHunt — тільки restricted.
