import os
import pandas as pd

# CONFIGURATION : chemins vers les fichiers et paramètres globaux
PYTHON_DIR = os.path.dirname(os.path.abspath(__file__))
ALERTE_DIR = os.path.join(PYTHON_DIR, "Fichiers_alerte")
if not os.path.exists(ALERTE_DIR):
    os.makedirs(ALERTE_DIR)
DATAFRAME_DIR = os.path.join(os.path.dirname(PYTHON_DIR), "Dataframes")
if not os.path.exists(DATAFRAME_DIR):
    os.makedirs(DATAFRAME_DIR) 

# DATAFRAME : Fichiers spécifiques et paramètres
CLEANED_CSV_FILE = os.path.join(DATAFRAME_DIR, "data_propre.csv")
DATA_EXISTENTE = os.path.join(DATAFRAME_DIR,"data_brut.csv")
FLUX_RSS = ["https://www.cert.ssi.gouv.fr/alerte/feed/","https://www.cert.ssi.gouv.fr/avis/feed/"]

# DATAFRAME : Colonnes propres au dataframe final
COLUMNS_DF = {
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
    "description_alerte": "Description",
    "epss_percentile": "EPSS_Percentile",
    "description_tech": "Description_Tech",
    "type_de_bulletin": "Type_de_Bulletin",
}

# ALERTE : Fichiers spécifiques
USER_DB = os.path.join(ALERTE_DIR, "mail_alerte.json")
LOG_FILE = os.path.join(ALERTE_DIR, "log_alerte.txt")
NEW_DATA_FILE = os.path.join(ALERTE_DIR, "nouvelles_alerte.csv")  

# ALERTE : Paramètres de l'email d'envoi
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_USER = "" # À remplir avec l'adresse email de l'expéditeur
SMTP_PASSWORD = "" # À remplir avec le mot de passe de l'expéditeur
COLUMNS_DF_ALERTE = ["ID_CVE", "Score_CVSS", "Gravite_CVSS","Titre_ANSSI", "ID_ANSSI", "Éditeur","Produit","Versions", "Lien_Bulletin", "Lien_Bulletin"]