import feedparser
import requests
import re


# Créons une liste avec tous les liens
url = "https://www.cert.ssi.gouv.fr/avis/feed/"
rss_feed = feedparser.parse(url)
liste_lien = [entry.link for entry in rss_feed.entries]
#print(liste_lien)

# Créons une liste avec toutes les CVE de chaque lien
#lien_test = 'https://www.cert.ssi.gouv.fr/avis/CERTFR-2025-AVI-1076/'
ref_cves = []
cve_unique = set()
for elem in liste_lien:
    url = elem+"json/"
    response = requests.get(url)
    data = response.json()
    #print(data)
    cves_du_bulletin = data['cves']
    # Cette étape sert à garder l'URL de l'alerte
    for cve in cves_du_bulletin:
        # cve_unique.add(cve)
        cve_unique.add(cve["name"])
        for systeme in data.get("affected_systems",[]):
            new_line = cve.copy()
            new_line["nom_vendeur"] = systeme.get('product',{}).get('vendor',{}).get('name')
            new_line["nom_produit"] = systeme.get('product',{}).get('name')
            new_line["version_info"] = systeme.get('description')
            new_line['source_alerte'] = elem
            new_line["id_alerte"] = data.get("reference")
            new_line["title_alerte"] = data.get("title")
            #Pour être certain que c'est bien la date de publication car il y a plusieurs date
            if len(data.get("revisions",[])) and data.get("revisions",[])[0]["description"] == "Version initiale":
                new_line["date_publication_alerte"] = data.get("revisions",[])[0]["revision_date"]
            new_line["description_alerte"] = data.get("risks",[])[0]["description"]
            ref_cves.append(new_line)
print(ref_cves)


# Test pour dataframe pandas

import pandas as pd

# 1) Création du DataFrame (pandas aligne automatiquement les clés ; valeurs manquantes -> NaN)
df = pd.DataFrame(ref_cves)

# 2) Optionnel : remettre de l'ordre + ne garder que les colonnes utiles
colonnes = [
    "name", "url",
    "nom_vendeur", "nom_produit", "version_info",
    "id_alerte", "title_alerte", "date_publication_alerte",
    "description_alerte", "source_alerte"
]
df = df.reindex(columns=[c for c in colonnes if c in df.columns])

# 3) Nettoyage léger (strings)
for col in ["name", "nom_vendeur", "nom_produit", "id_alerte", "title_alerte", "source_alerte"]:
    if col in df.columns:
        df[col] = df[col].astype("string").str.strip()

# 4) Date -> datetime (si la colonne existe)
if "date_publication_alerte" in df.columns:
    df["date_publication_alerte"] = pd.to_datetime(df["date_publication_alerte"], errors="coerce", utc=True)

# 5) Supprimer les doublons (souvent un bon choix)
# Ici : même CVE + même produit + même alerte
subset = [c for c in ["name", "nom_vendeur", "nom_produit", "id_alerte"] if c in df.columns]
if subset:
    df = df.drop_duplicates(subset=subset).reset_index(drop=True)

print(df.head())



