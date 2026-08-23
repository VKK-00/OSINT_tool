# План міграції: osintkit → osint_toolkit

Статус: пропозиція (draft). Мета — прибрати дублювання між двома пакетами й залишити **один рушій** та один UI-шар.

## Поточний стан

| | `osint_toolkit` | `osintkit` |
|---|---|---|
| Роль | основний движок: unified search/investigate, adapter-шар, case store, toolbox | автономний deep-пакет: sanctions/leaks індекси, EXIF, веб-UI, watch |
| Модель результатів | `Finding`/`Entity` + graph | власні report structures |
| Дублі концептів | `modules/dorks.py`, `modules/telegram.py`, `modules/username.py`, `output.py` | ті самі напрямки: `modules/dorks.py`, `modules/telegram.py`, `modules/username.py`, `output.py` |

Проблема: кожна нова фіча фактично робиться двічі, а parity-карта доводиться підтримувати для обох фронтендів.

## Цільова архітектура

```
osint_toolkit/          # єдиний рушій
  engine / search / investigation / case_store / adapters
  modules/              # усі native-модулі, включно з deep-index
osintkit/               # тонкий шар сумісності
  __main__.py           # CLI -> виклики osint_toolkit
  webapp.py             # веб-UI/watch залишається тут (окремий UX)
  store.py, report_html # залишаються, поки веб-UI залежить від них
```

Правило після міграції: **бізнес-логіка живе тільки в `osint_toolkit`; `osintkit` не містить нових scan-реалізацій**, лише CLI/web UX над рушієм.

## Етапи

### Етап 0 — підготовка (без зміни поведінки)

1. Зафіксувати контракт: `Finding`, `Entity`, edge-типи, статуси/confidence — вже описані в README; винести в `docs/CONTRACT.md`, щоб обидва пакети посилались на один документ.
2. Додати parity-тести: для кожного deep-модуля `osintkit` — тест, що той самий seed через `osint_toolkit.search` дає еквівалентні findings (вже частково є в `tests/test_deep_bridges.py`).

### Етап 1 — bridge замість дублів

3. `osintkit/modules/dorks.py`, `telegram.py`, `username.py` переводяться на делегування до відповідних модулів `osint_toolkit/modules/*` (адаптація результатів у формат звітів osintkit). Пріоритет порядку: dorks → telegram → username.
4. Видалити код-дублікати, що лишаться мертвими після делегування; оновити `UPSTREAM_PARITY.ru.md` (рядки "native" стосуються тепер тільки однієї реалізації).

### Етап 2 — спільна модель даних

5. `osintkit/core.py` переходить на `osint_toolkit.models.Finding` внутрішньо; конвертація у власний JSON-формат звіту лишається тільки на межі виводу (`osintkit/output.py`) для зворотної сумісності існуючих скриптів/watch-дифів.

### Етап 3 — консолідація CLI

6. `python -m osintkit scan ...` стає обгорткою над `osint_toolkit.scan`-шаром; прапорці CLI не змінюються.
7. `sanctions-update`, `leaks-import` та індексація — перенести як команди `tools`/`scan` в `osint_toolkit.cli`, а в `osintkit` лишити deprecated-аліаси з warning.

### Етап 4 — веб-UI

8. `webapp.py` читає кейси/findings через `case_store`-шар `osint_toolkit` (спільний SQLite), зберігаючи власний watch-моніторинг і NEW-диф.
9. Прибрати подвійне зберігання (`out/index.db` vs case-db) — одна БД, два клієнти.

## Критерії завершення

- [ ] Жоден модуль не існує в двох реалізаціях; grep по дублях назв дає тільки re-export/делегування.
- [ ] Усі тести проходять без зміни очікувань поведінки CLI обох пакетів.
- [ ] `UPSTREAM_PARITY.ru.md` посилається на одну реалізацію кожної здібності.
- [ ] Веб-UI osintkit працює на спільному case store.

## Ризики

- Зворотна сумісність JSON-звітів osintkit (watch-диф) — тримаємо конвертер на межі виводу щонайменше один мінорний реліз.
- Розмір PR: робити по одному етапу = окремий merge, без "великого вибуху".
