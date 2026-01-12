

import pandas as pd

df = pd.read_csv('data_brut.csv', dtype=str)
colonne_numerique = ["cvss", "epss", "epss_percentile"]
for colonne in colonne_numerique:
    df[colonne] = pd.to_numeric(df[colonne], errors='coerce')
df["date_publication_alerte"] = pd.to_datetime(df["date_publication_alerte"], errors="coerce", utc=True).dt.date

def avis_ou_alerte(ref):
    if "AVI" in str(ref): return "Avis"
    if "ALE" in str(ref): return "Alerte"
    return "Autre"

df["type_de_bulletin"] = df["id_alerte"].apply(avis_ou_alerte)
mapping = {
    "name": "ID_CVE",
    "cvss": "Score_CVSS",
    "cvss_gravite": "Gravite_CVSS",
    "epss": "Score_EPSS",
    "cwe_id": "Type_CWE",
    "title_alerte": "Titre_ANSSI",
    "id_alerte": "ID_ANSSI",
    "date_publication_alerte": "Date_Publication",
    "nom_vendeur": "Éditeur",
    "nom_produit": "Produit",
    "version_info": "Versions",
    "source_alerte": "Lien_Bulletin",
    "cvss_vecteur": "Vecteur_CVSS",
    "description_alerte": "Description"
}
df = df.rename(columns=mapping)
#print(df.head(10))
#print(df[df["type_de_bulletin"] == "Alerte"])
df.to_csv('data_propre.csv', index=False)