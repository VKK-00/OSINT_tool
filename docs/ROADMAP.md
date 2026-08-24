# Roadmap

## v0.1 (поточний стан)
- [x] Модульне ядро: реєстр, HTTP з rate-limit/UA-ротацією, Finding-модель
- [x] username (30+ платформ, UA/RF-пріоритет, транслітерація)
- [x] phone (офлайн-метадані phonenumbers)
- [x] email (gravatar, XposedOrNot)
- [x] net (DoH, crt.sh, rdap.org)
- [x] tg (публічний прев'ю t.me/s без API)
- [x] archive (wayback availability + SPN)
- [x] geo (мапи, Nominatim, оцінка часу зйомки за тінню)
- [x] JSON-звіти

## v0.2 (поточний стан)
- [x] Веб-інтерфейс: FastAPI + SPA (модулі, прогрес, NEW-бейджі, історія, панель даних)
- [x] opensanctions: локальний пошук по санкційних списках (OFAC/ЄС)
- [x] Локальний індекс витоків: імпорт user-supplied датасетів + grep-пошук
- [x] Диф-моніторинг: позначення нових знахідок між сканами
- [x] tg: історія каналів без API-ключів (?before= пагінація) — pyrogram більше не потрібен
- [x] Паралельний username-скан + og:title enrichment + FP-фільтри
- [x] Retry/backoff у HTTP-клієнті
- [x] HTML-звіт з графом зв'язків

## v0.3 (поточний стан)
- [x] Персо-OSINT збагачення з публічних джерел: GitHub/Mastodon/Bluesky профілі (username), Wikidata дізамбігуація осіб (person), Gravatar-профіль (email live)
- [x] Доменна розвідка: Shodan InternetDB IP-exposure, Wayback CDX вік домену, urlScan history (за ключем оператора); UA/RF публічні реєстри в ru-ua source pack
- [x] Legal-пошук (CourtListener), OTX passive DNS; recon-ng/auto-archiver експериментальні адаптери (env-конфігурація)
- [x] Unified Watch: `watch` команда з entity-level diff у спільному case store (--cycles/--interval-min, live case перезаписується щоцикл)
- [x] `investigate --from-file` і `watch --from-file`: batch таргети з файлу (kind=value або auto-classify)
- [x] GEXF 1.3 експорт графа кейса для Gephi/yEd (`case-graph --format gexf`)
- [x] Monthly snapshot cron workflow (авто-PR при оновленні upstream датасетів)
- [x] Source pack: FSSP РФ, Розшук МВС УКРАЇНИ, UK PSC Register
- [x] Passive-DNS hostnames (HackerTarget, keyless) + UK Companies House (free key) у company-напрямі; scripts/update_snapshots.py для Sherlock/WMN снапшотів
- [x] SOCMINT-глибина: останні публічні пости Mastodon та Bluesky author feed у live username-сканах
- [x] Новий target kind `company`: GLEIF open lookup (ім'я або LEI) + профіль `company-safe`
- [x] EXIF GPS + Overpass: найближчі іменовані OSM-об'єкти для верифікації геолокації фото
- [x] Evidence-graph семантика: planned/not_found/skipped/error більше не створюють сутностей і зв'язків (probe/observation/assertion split)
- [x] Веббезпека: токен лише заголовком, non-loopback bind потребує токен, script-safe JSON у HTML-звітах, CSV formula-defense
- [x] Залежності оголошені повністю (base/web/dev extras), CI чисто встановлює wheel і smoke-тестить усі entry points
- [x] Case store: guard від новішої схеми, lookup-індекси; leaks: raw lines вимкнені за замовчуванням, purge CLI
- [ ] Консолідація пакетів: osintkit стає тонким CLI/web-шаром над рушієм osint_toolkit — план у [MIGRATION_OSINTKIT.uk.md](MIGRATION_OSINTKIT.uk.md)
- [x] Module registry: профілі обирають конкретні module IDs (network_access/risk_tier/requires_key), tri-state native_modules (None/()/allowlist), snapshot-тести складу
- [ ] Confidence model split: source/identity/assertion confidence + severity + corroboration_count замість однієї low/medium/high шкали
- [x] Watch osintkit пише рескани в спільний case store; leaks/sanctions мігрували в out/cases.sqlite (авто-міграція з index.db)

## Ідеї
- Зовнішні публічні джерела (InternetDB, Wayback CDX, Mastodon/Bluesky lookup, Overpass, GLEIF тощо) — пріоритезований план у [EXTERNAL_INTEGRATIONS.uk.md](EXTERNAL_INTEGRATIONS.uk.md)
- Пошук по судових реєстрах UA/RF (публічні API)
- Інтеграція KartaView/Mapillary для вуличного рівня геолокації
- Розпізнавання номерних знаків (локальна модель) для верифікації фото
