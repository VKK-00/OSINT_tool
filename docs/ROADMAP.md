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

## v0.3
- [ ] Консолідація пакетів: osintkit стає тонким CLI/web-шаром над рушієм osint_toolkit — план у [MIGRATION_OSINTKIT.uk.md](MIGRATION_OSINTKIT.uk.md)
- [ ] Моніторинг: diff між сканами каналу/профілю у часі
- [ ] Інтеграція bellingcat auto-archiver для медіа
- [ ] Веб-UI (FastAPI + проста мапа результатів)
- [ ] Плагінний API для сторонніх модулів

## Ідеї
- Зовнішні публічні джерела (InternetDB, Wayback CDX, Mastodon/Bluesky lookup, Overpass, GLEIF тощо) — пріоритезований план у [EXTERNAL_INTEGRATIONS.uk.md](EXTERNAL_INTEGRATIONS.uk.md)
- Пошук по судових реєстрах UA/RF (публічні API)
- Інтеграція KartaView/Mapillary для вуличного рівня геолокації
- Розпізнавання номерних знаків (локальна модель) для верифікації фото
