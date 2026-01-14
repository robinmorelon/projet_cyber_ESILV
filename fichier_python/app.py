import streamlit as st
import os
import pandas as pd
import json
from datetime import datetime, timedelta

st.set_page_config(page_title="Projet cyber ESILV", layout="wide")
st.title("Dashboard de Vulnérabilités & Configuration Alertes")

DOSSIER = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(DOSSIER, 'data_propre.csv')
USER_DB = os.path.join("Data", "mail_alerte.json")


@st.cache_data
def load_data():
    df = pd.read_csv(DATA)
    # On fausse un peu la réalité ici en remplacant les valeurs nuls par 0 mais c'est utile pour ne pas perdre de données avec les filtres
    # Pour les visualisations, les valeurs n'ont pas étés modifiées pour garder la réalité
    df['Date_Publication'] = pd.to_datetime(df['Date_Publication'], errors='coerce')
    if "Score_CVSS" in df.columns:
        df["Score_CVSS"] = df["Score_CVSS"].fillna(0)
    return df


def save_alert_config(email, filtres, colonne_cible):
    if os.path.exists(USER_DB):
        with open(USER_DB, "r", encoding='utf-8') as f:
            users = json.load(f)
    else:
        users = {}
    users[email] = {
        "colonne_cible": colonne_cible,
        "filtres": filtres
    }
    with open(USER_DB, "w", encoding='utf-8') as f:
        json.dump(users, f, indent=4, ensure_ascii=False)


tab1, tab2 = st.tabs(["📊 Exploration des données", "🔔 Configuration des Alertes"])
df = load_data()

if df is None:
    st.error(f"Le fichier {DATA} est introuvable.")
else:
    with tab1:
        st.sidebar.header("Filtres d'exploration")
        df_filtered = df.copy()
        choix_periode = st.sidebar.selectbox(
            "Période de publication",
            ["Tout l'historique", "Dernières 24h", "7 derniers jours", "30 derniers jours"]
        )
        date_jour = datetime.now().date()
        start_date = None
        end_date = date_jour
        if choix_periode == "Dernières 24h":
            start_date = date_jour - timedelta(days=1)  # Aujourd'hui + Hier
        elif choix_periode == "7 derniers jours":
            start_date = date_jour - timedelta(days=7)
        elif choix_periode == "30 derniers jours":
            start_date = date_jour - timedelta(days=30)
        if choix_periode != "Tout l'historique":
            # On filtre df_filtered et on le met à jour
            mask_date = (df_filtered["Date_Publication"].dt.date >= start_date) & \
                        (df_filtered["Date_Publication"].dt.date <= end_date)
            df_filtered = df_filtered[mask_date]
        liste_editeurs_dispo = df_filtered["Éditeur"].unique()
        selected_vendor = st.sidebar.multiselect("Filtrer par Éditeur", options=liste_editeurs_dispo)
        min_score = st.sidebar.slider("Score CVSS Minimum", 0.0, 10.0, 0.0)
        df_filtered = df_filtered[df_filtered["Score_CVSS"] >= min_score]
        if selected_vendor:
            df_filtered = df_filtered[df_filtered["Éditeur"].isin(selected_vendor)]


        if selected_vendor:
            df_filtered = df_filtered[df_filtered["Éditeur"].isin(selected_vendor)]

        col1, col2, col3 = st.columns(3)
        nb_cve_unique = df_filtered["ID_CVE"].nunique()
        col1.metric("Total CVE unique", nb_cve_unique)
        df_cve_unique = df_filtered.drop_duplicates(subset=["ID_CVE"])
        avg_score = df_cve_unique["Score_CVSS"].mean()
        col2.metric("Score CVSS Moyen", f"{avg_score:.2f}" if not pd.isna(avg_score) else "N/A")
        nb_critique = len(df_cve_unique[df_cve_unique["Gravite_CVSS"] == "CRITICAL"])
        #len(df_filtered[df_filtered["Gravite_CVSS"] == "CRITICAL"])
        col3.metric("Vulnérabilités Critiques", nb_critique)

        st.subheader("Données Détaillées")
        st.dataframe(df_filtered)