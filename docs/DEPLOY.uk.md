# Р”РµРїР»РѕР№: РїРѕСЃС‚С–Р№РЅРёР№ РјРѕРЅС–С‚РѕСЂРёРЅРі

РЇРєС‰Рѕ С…РѕС‡РµС€, С‰РѕР± watch-РјРѕРЅС–С‚РѕСЂРёРЅРі РїСЂР°С†СЋРІР°РІ 24/7 (Р° РЅРµ РїРѕРєРё РІС–РґРєСЂРёС‚Р° РєРѕРЅСЃРѕР»СЊ),
РѕСЃРµР»Рё РІРµР±-UI СЏРє СЃРµСЂРІС–СЃ. РќРёР¶С‡Рµ вЂ” РїРµСЂРµРІС–СЂРµРЅС– РІР°СЂС–Р°РЅС‚Рё РґР»СЏ Windows С– Linux.

## 0. РџС–РґРіРѕС‚РѕРІРєР° (РѕРґРёРЅ СЂР°Р·)

```bash
git clone https://github.com/VKK-00/OSINT_tool.git
cd OSINT_tool
pip install -e ".[dev]"
python -m osintkit sanctions-update          # ~100 MB, РѕС„Р»Р°Р№РЅ-С–РЅРґРµРєСЃ СЃР°РЅРєС†С–Р№
python -m osintkit leaks-import ./leaks/     # РѕРїС†С–Р№РЅРѕ: СЃРІРѕС— РґР°С‚Р°СЃРµС‚Рё
# С‚Рµ Р¶ СЃР°РјРµ Р· СѓРЅС–С„С–РєРѕРІР°РЅРѕРіРѕ CLI:
# python -m osint_toolkit deep-sanctions-update && python -m osint_toolkit deep-leaks-import ./leaks/
```

## 1. Windows вЂ” Task Scheduler

```powershell
# СЂРµС”СЃС‚СЂСѓС”РјРѕ Р°РІС‚РѕР·Р°РїСѓСЃРє РїСЂРё РІС…РѕРґС– РєРѕСЂРёСЃС‚СѓРІР°С‡Р°
$action  = New-ScheduledTaskAction -Execute "python" `
           -Argument "-m uvicorn osintkit.webapp:app --host 127.0.0.1 --port 8765" `
           -WorkingDirectory "C:\OSINT_tool"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "osintkit-web" -Action $action -Trigger $trigger
```

РђР±Рѕ С‡РµСЂРµР· [NSSM](https://nssm.cc) (СЃРїСЂР°РІР¶РЅС–Р№ СЃРµСЂРІС–СЃ, РїРµСЂРµР¶РёРІР°С” РІРёС…С–Рґ Р· СЃРµСЃС–С—):

```powershell
nssm install osintkit-web "C:\Python314\python.exe" "-m uvicorn osintkit.webapp:app --host 127.0.0.1 --port 8765"
nssm set osintkit-web AppDirectory C:\OSINT_tool
nssm start osintkit-web
```

## 2. Linux (VPS) вЂ” systemd

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

## 3. Р‘РµР·РїРµРєР°

- РЎР»СѓС…Р°Р№ **С‚С–Р»СЊРєРё 127.0.0.1**. Р”Р»СЏ РІС–РґРґР°Р»РµРЅРѕРіРѕ РґРѕСЃС‚СѓРїСѓ вЂ” SSH-С‚СѓРЅРµР»СЊ:
  `ssh -L 8765:127.0.0.1:8765 user@vps`
- РЇРєС‰Рѕ С‚СЂРµР±Р° РІС–РґРєСЂРёС‚Рё РїРѕСЂС‚ вЂ” СѓРІС–РјРєРЅРё СЃРїС–Р»СЊРЅРёР№ С‚РѕРєРµРЅ:
  `python -m osintkit.webapp --host 0.0.0.0 --token <РґРѕРІС–Р»СЊРЅРёР№-СЂСЏРґРѕРє>`
  (Р°Р±Рѕ env `OSINTKIT_WEBAPP_TOKEN`). Р‘СЂР°СѓР·РµСЂ СЃР°Рј РїРѕРїСЂРѕСЃРёС‚СЊ С‚РѕРєРµРЅ РѕРґРёРЅ СЂР°Р·
  С– Р·Р±РµСЂРµР¶Рµ Р№РѕРіРѕ РІ localStorage.
- Watch'С– Р·Р±РµСЂС–РіР°СЋС‚СЊСЃСЏ РІ `out/watches.json` С– РІС–РґРЅРѕРІР»СЋСЋС‚СЊСЃСЏ РїС–СЃР»СЏ СЂРµСЃС‚Р°СЂС‚Сѓ
  СЃРµСЂРІС–СЃР° вЂ” РґРµРїР»РѕР№ РЅС–С‡РѕРіРѕ РЅРµ РІС‚СЂР°С‡Р°С”.
- Р‘РµРєР°РїСЊ `out/` (Р·РІС–С‚Рё + `index.db` + `cases.sqlite` + `watches.json`).

## 4. РџРµСЂРµРІС–СЂРєР°

```bash
curl http://127.0.0.1:8765/api/meta        # в†’ {"version": ...}
```

РџС–СЃР»СЏ СЂРµСЃС‚Р°СЂС‚Сѓ СЃРµСЂРІС–СЃР°: watch'С– РІС–РґРЅРѕРІРёР»РёСЃСЊ в†’ Сѓ Р±С–С‡РЅС–Р№ РїР°РЅРµР»С– В«РњРѕРЅС–С‚РѕСЂРёРЅРіВ»
Р·РЅРѕРІСѓ Р°РєС‚РёРІРЅС–, РїРµСЂС€РёР№ С†РёРєР» РєРѕР¶РЅРѕРіРѕ Р·Р°РїСѓСЃС‚РёС‚СЊСЃСЏ Р°РІС‚РѕРјР°С‚РёС‡РЅРѕ.
