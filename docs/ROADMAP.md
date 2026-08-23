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

## v0.2
- [ ] opensanctions: локальний пошук по санкційних списках (OFAC/ЄС)
- [ ] Локальний індекс витоків: імпорт user-supplied датасетів + grep-пошук
- [ ] tg: історія каналу через pyrogram (опційний API-ключ)
- [ ] Пагінація username-скану, retry/backoff
- [ ] HTML-звіт з графом зв'язків

## v0.3
- [ ] Моніторинг: diff між сканами каналу/профілю у часі
- [ ] Інтеграція bellingcat auto-archiver для медіа
- [ ] Веб-UI (FastAPI + проста мапа результатів)
- [ ] Плагінний API для сторонніх модулів

## Ідеї
- Пошук по судових реєстрах UA/RF (публічні API)
- Інтеграція KartaView/Mapillary для вуличного рівня геолокації
- Розпізнавання номерних знаків (локальна модель) для верифікації фото
