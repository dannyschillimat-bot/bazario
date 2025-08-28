import csv, sqlite3

DB_PATH = "bazario.db"
CSV_PATH = "de_plz.csv"

conn = sqlite3.connect(DB_PATH)
conn.execute("PRAGMA foreign_keys = ON")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS plz (
    plz TEXT PRIMARY KEY,
    ort TEXT NOT NULL,
    lat REAL NOT NULL,
    lon REAL NOT NULL
)
""")

with open(CSV_PATH, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f, delimiter=";")
    rows = [(r["plz"], r["ort"], float(r["lat"]), float(r["lon"])) for r in reader]

cur.execute("DELETE FROM plz")  # frisch befüllen
cur.executemany("INSERT INTO plz (plz, ort, lat, lon) VALUES (?, ?, ?, ?)", rows)
conn.commit()
conn.close()
print(f"Import fertig: {len(rows)} PLZs geladen.")
