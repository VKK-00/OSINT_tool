# Спільний контракт даних (osint_toolkit <-> osintkit)

Єдине джерело правди для моделей результатів. Обидва пакети зобов'язані тримати
сумісність із цим контрактом; будь-яка зміна — тільки через цей документ.

## Рушійна модель (`osint_toolkit.engine.Finding`)

| Поле | Тип | Зміст |
|---|---|---|
| `module` | str | ім'я модуля-джерела (наприклад `username-public-profiles`, `dorks`) |
| `source` | str | конкретне джерело всередині модуля (сайт, сервіс, `normalizer`) |
| `target` | str | початковий seed-рядок скану |
| `status` | str | див. нижче |
| `url` | str | головний URL доказу |
| `title` | str | заголовок сторінки/людини-півота |
| `http_status` | int \| None | HTTP статус, якщо був запит |
| `confidence` | str | `low / medium / high / unknown / not_checked` |
| `evidence` | str | людське пояснення класифікації |
| `metadata` | dict[str, str] | додаткові сигнали (тільки рядки) |
| `checked_at` | str | ISO-moment перевірки |

### Статуси

- `planned` — dry-run, запит не робився;
- `candidate` — знайдено/існує (підтвердження маркером чи статусом);
- `not_found` — перевірено і відсутнє;
- `skipped` — не застосововано до цього таргета (правило платформи);
- `invalid` — таргет не нормалізувався;
- `unknown` — запит був, відповідь неоднозначна (403/429/5xx тощо);
- `error` — помилка виконання;
- `hit` — спрацював локальний індекс (sanctions/leaks).

## Суміснісна модель osintkit (`osintkit.core.Finding`)

Поля `kind / source / value / confidence / url / extra`. Це **формат виводу**
легасі-CLI і веб-UI; рушійна логіка має жити на `engine.Finding`.

### Правила конвертації engine -> core (див. `osintkit/bridge.py`)

- `kind` = рід знахідки модуля (`dork`, `lead`, `channel`, `post`, `history`, `profile`);
- `source` = `finding.source` (сайт або сервіс), для bridge-модулів додається суфікс `(username)` за потреби UI;
- `value` = людський текст: `title` або `evidence`;
- `confidence` = `finding.confidence`, `unknown/not_checked` -> `low`;
- `url` = `finding.url`;
- `extra` = `finding.metadata` + `title`/`status`/`http_status` для трасування.

## Спільні утиліти

- Транслітерація: єдина реалізація `osint_toolkit.translit.transliterate`;
  `osintkit.core.transliterate` лише реекспортує її.
- Username-sites DB: єдина `osint_toolkit.sites.USERNAME_SITES`; curated
  UA/RF-підмножина osintkit вибирається з неї за `url_template`, дублікати
  сайтів заборонені.

## Заборони

- Нові scan-реалізації в `osintkit/modules/*` заборонені: тільки делегування
  до `osint_toolkit` + конвертація.
- Не можна вводити третій формат результатів.
