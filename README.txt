Bazario (Demo)
=================

Schnellstart:
1) Python 3 installieren.
2) In diesem Ordner:
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # macOS/Linux:
   source .venv/bin/activate
   pip install -r requirements.txt
3) Datenbank initialisieren (Tabellen werden beim Start angelegt):
   python app.py  (mit STRG+C wieder stoppen)
4) PLZ importieren:
   python import_plz.py
5) Starten:
   python app.py
   -> http://127.0.0.1:5000

Admin aktivieren:
- User registrieren (E-Mail).
- App mit gesetzter Env-Variable starten:
  # Windows (PowerShell):  $env:BAZARIO_ADMIN_EMAIL="dein-admin@beispiel.de"; python app.py
  # macOS/Linux:           export BAZARIO_ADMIN_EMAIL="dein-admin@beispiel.de"; python app.py
