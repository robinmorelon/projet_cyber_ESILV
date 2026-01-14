from config import DATA_EXISTENTE, CLEANED_CSV_FILE, COLUMNS_DF, pd

# Nettoyage et transformation du dataframe brut
def nettoyage_df(data_brut=DATA_EXISTENTE, data_propre=CLEANED_CSV_FILE):
    df = pd.read_csv(data_brut, dtype=str)
    colonne_numerique = ["cvss", "epss", "epss_percentile"]

    for colonne in colonne_numerique:
        df[colonne] = pd.to_numeric(df[colonne], errors='coerce')
    df["date_publication_alerte"] = pd.to_datetime(df["date_publication_alerte"], errors="coerce", utc=True).dt.date
    df["type_de_bulletin"] = df["id_alerte"].apply(avis_ou_alerte)

    df = df.rename(columns=COLUMNS_DF)
    df.to_csv(data_propre, index=False)
    return df


# Ajout de la colonne Type_de_Bulletin
def avis_ou_alerte(ref):
    if "AVI" in str(ref): return "Avis"
    if "ALE" in str(ref): return "Alerte"
    return "Autre"