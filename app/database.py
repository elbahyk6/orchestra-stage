import sqlite3
import json
import os
from datetime import datetime
from core.encryption import encrypt, decrypt

DB_PATH = os.getenv("DB_PATH", "/app/data/orchestra.db")


def init_db():
    """Crée la base de données et la table si elles n'existent pas"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT    NOT NULL DEFAULT 'anonymous',
            cible       TEXT    NOT NULL,
            type_scan   TEXT    NOT NULL,
            outils      TEXT    NOT NULL,
            findings    TEXT    NOT NULL,
            synthese    TEXT    NOT NULL,
            timestamp   TEXT    NOT NULL,
            nb_critique INTEGER DEFAULT 0,
            nb_moyen    INTEGER DEFAULT 0,
            nb_faible   INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()
    print("[DB] Base de données initialisée")


def sauvegarder_scan(cible, type_scan, outils, findings, synthese, session_id):
    """Sauvegarde un scan dans la base de données"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    nb_critique = len([f for f in findings if f.get("severite") == "high"])
    nb_moyen    = len([f for f in findings if f.get("severite") == "medium"])
    nb_faible   = len([f for f in findings if f.get("severite") == "low"])

    cursor.execute("""
        INSERT INTO scans
        (session_id, cible, type_scan, outils, findings,
         synthese, timestamp, nb_critique, nb_moyen, nb_faible)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        session_id,
        cible,
        type_scan,
        json.dumps(outils),
        encrypt(json.dumps(findings)), # Chiffrement de la chaîne JSON
        encrypt(synthese),             # Chiffrement de la synthèse
        datetime.now().isoformat(),
        nb_critique,
        nb_moyen,
        nb_faible
    ))
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    print(f"[DB] Scan sauvegardé — ID {scan_id} | Session {session_id[:8]}...")
    return scan_id


def get_historique(limite=10, session_id=None):
    """Retourne les derniers scans de la session"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if session_id:
        cursor.execute("""
            SELECT id, cible, type_scan, outils, timestamp,
                   nb_critique, nb_moyen, nb_faible
            FROM scans
            WHERE session_id = ?
            ORDER BY id DESC
            LIMIT ?
        """, (session_id, limite))
    else:
        cursor.execute("""
            SELECT id, cible, type_scan, outils, timestamp,
                   nb_critique, nb_moyen, nb_faible
            FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limite,))

    rows = cursor.fetchall()
    conn.close()

    return [{
        "id":          row[0],
        "cible":       row[1],
        "type_scan":   row[2],
        "outils":      json.loads(row[3]),
        "timestamp":   row[4],
        "nb_critique": row[5],
        "nb_moyen":    row[6],
        "nb_faible":   row[7]
    } for row in rows]


def get_scan_par_id(scan_id, session_id=None):
    """Retourne un scan complet par son ID — vérifie la session"""
    conn = sqlite3.connect(DB_PATH)
    # Permet d'accéder aux données par nom de colonne (ex: row["findings"])
    conn.row_factory = sqlite3.Row 
    cursor = conn.cursor()

    if session_id:
        cursor.execute("""
            SELECT * FROM scans
            WHERE id = ? AND session_id = ?
        """, (scan_id, session_id))
    else:
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id":          row["id"],
        "session_id":  row["session_id"],
        "cible":       row["cible"],
        "type_scan":   row["type_scan"],
        "outils":      json.loads(row["outils"]),
        "findings":    json.loads(decrypt(row["findings"])), # Déchiffrement + Parse JSON
        "synthese":    decrypt(row["synthese"]),             # Déchiffrement
        "timestamp":   row["timestamp"],
        "nb_critique": row["nb_critique"],
        "nb_moyen":    row["nb_moyen"],
        "nb_faible":   row["nb_faible"]
    }


def get_scans_par_cible(cible, session_id=None):
    """Retourne tous les scans d'une cible pour comparaison"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if session_id:
        cursor.execute("""
            SELECT id, timestamp, nb_critique, nb_moyen, nb_faible
            FROM scans WHERE cible = ? AND session_id = ?
            ORDER BY id DESC
        """, (cible, session_id))
    else:
        cursor.execute("""
            SELECT id, timestamp, nb_critique, nb_moyen, nb_faible
            FROM scans WHERE cible = ?
            ORDER BY id DESC
        """, (cible,))

    rows = cursor.fetchall()
    conn.close()

    return [{
        "id":          row[0],
        "timestamp":   row[1],
        "nb_critique": row[2],
        "nb_moyen":    row[3],
        "nb_faible":   row[4]
    } for row in rows]