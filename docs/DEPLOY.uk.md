# Деплой: постійний моніторинг

Якщо хочеш, щоб watch-моніторинг працював 24/7 (а не поки відкрита консоль),
осели веб-UI як сервіс. Нижче — перевірені варіанти для Windows і Linux.

## 0. Підготовка (один раз)

```bash
git clone https://github.com/VKK-00/OSINT_tool.git
cd OSINT_tool
pip install -e ".[dev]"
python -m osintkit sanctions-update        # ~100 MB, офлайн-індекс санкцій
python -m osintkit leaks-import ./leaks/   # опційно: свої датасети
```

## 1. Windows — Task Scheduler

```powershell
# реєструємо автозапуск при вході користувача
$action  = New-ScheduledTaskAction -Execute "python" `
           -Argument "-m uvicorn osintkit.webapp:app --host 127.0.0.1 --port 8765" `
           -WorkingDirectory "C:\OSINT_tool"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "osintkit-web" -Action $action -Trigger $trigger
```

Або через [NSSM](https://nssm.cc) (справжній сервіс, переживає вихід з сесії):

```powershell
nssm install osintkit-web "C:\Python314\python.exe" "-m uvicorn osintkit.webapp:app --host 127.0.0.1 --port 8765"
nssm set osintkit-web AppDirectory C:\OSINT_tool
nssm start osintkit-web
```

## 2. Linux (VPS) — systemd

```ini
# /etc/systemd/system/osintkit-web.service
[Unit]
Description=osintkit web UI
After=network-online.target

[Service]
User=osint
WorkingDirectory=/opt/OSINT_tool
ExecStart=/opt/OSINT_tool/.venv/bin/python -m osintkit.webapp --host 127.0.0.1 --port 8765 --token ${OSINTKIT_TOKEN}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now osintkit-web
```

## 3. Безпека

- Слухай **тільки 127.0.0.1**. Для віддаленого доступу — SSH-тунель:
  `ssh -L 8765:127.0.0.1:8765 user@vps`
- Якщо треба відкрити порт — увімкни спільний токен:
  `python -m osintkit.webapp --host 0.0.0.0 --token <довільний-рядок>`
  (або env `OSINTKIT_WEBAPP_TOKEN`). Браузер сам попросить токен один раз
  і збереже його в localStorage.
- Watch'і зберігаються в `out/watches.json` і відновлюються після рестарту
  сервіса — деплой нічого не втрачає.
- Бекапь `out/` (звіти + `index.db` + `cases.sqlite` + `watches.json`).

## 4. Перевірка

```bash
curl http://127.0.0.1:8765/api/meta        # → {"version": ...}
```

Після рестарту сервіса: watch'і відновились → у бічній панелі «Моніторинг»
знову активні, перший цикл кожного запуститься автоматично.
