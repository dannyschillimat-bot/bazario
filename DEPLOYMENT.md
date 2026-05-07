# X-Markt.de Deployment

Diese Version ist keine statische Demo mehr, sondern eine Flask-App mit Login, Datenbank, Uploads, Anzeigen und Nachrichtenbasis.

## Pflicht vor dem Onlinegang

1. `SECRET_KEY` als lange zufaellige Zeichenkette setzen.
2. `SESSION_COOKIE_SECURE=1` setzen, sobald HTTPS aktiv ist.
3. `DATABASE_PATH` auf einen persistenten Speicherpfad setzen.
4. `UPLOAD_FOLDER` auf einen persistenten Upload-Ordner setzen.
5. HTTPS erzwingen, z. B. ueber Reverse Proxy oder Hosting-Anbieter.
6. Regelmaessige Backups fuer Datenbank und Uploads einrichten.

## Lokal starten

```powershell
cd H:\X-Markt.de
python app.py
```

Dann im Browser oeffnen:

```text
http://localhost:5000
```

## Hosting-Empfehlung

Fuer diese SQLite-Version passt ein VPS oder Webhost mit persistentem Dateisystem besser als serverlose Plattformen.

Gute naechste Ausbaustufe fuer groessere Nutzung:

- PostgreSQL statt SQLite
- Objekt-Speicher fuer Bilder
- E-Mail-Verifizierung und Passwort-Reset
- Moderationsbereich fuer Meldungen
- Rate-Limiting und Spam-Schutz
- AGB, Datenschutz und Impressum rechtlich finalisieren
