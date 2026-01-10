import os

# Paramètres de l'email d'envoi
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_USER = "salvetti.regis@gmail.com"
# Le mot de passe sera demandé une seule fois lors du lancement du script
SMTP_PASSWORD = input("Entrez le mot de passe application Gmail : ")  

# Configuration des chemins vers les fichiers de données
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "Data")
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# Fichiers spécifiques
USER_DB = os.path.join(DATA_DIR, "mail_alerte.json")
LAST_DATA_FILE = os.path.join(DATA_DIR, "scan_alerte.csv")
LOG_FILE = os.path.join(DATA_DIR, "log_envois.txt")