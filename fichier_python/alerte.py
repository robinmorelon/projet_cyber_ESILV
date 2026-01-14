from getpass import getpass
from datetime import datetime
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart  
# Importation des paramètres de configuration
from config import SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD
from config import USER_DB, LOG_FILE, NEW_DATA_FILE, COLUMNS_DF_ALERTE, os, pd 

# Enregistrement des logs d'envoi
def log_validation(email, alert, nb_cve, status="Succès"):
    horodatage = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[{horodatage}] Envoi à : {email} | alerte : {alert} | CVE envoyées : {nb_cve} | Statut : {status}\n"
    
    # Mode 'a' pour 'append' (ajout à la fin du fichier sans effacer le reste)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg)


# Envoi des emails d'alerte
def send_alert_email(to_email, user_filtred_col, user_filtred_items, df_new):
    # Filtrage selon les thèmes choisis par l'utilisateur
    df_filtered = df_new[df_new[user_filtred_col].isin(user_filtred_items)]   
    if df_filtered.empty: 
        return  # Rien à envoyer
    
    # Construction du mail
    msg = MIMEMultipart()
    msg['From'] = "projet_python@esilv.fr"
    msg['To'] = to_email
    msg['Subject'] = "Alerte Sécurité : nouvelles vulnérabilités détectées"

    # Construction du corps du mail HTML
    html_table = df_filtered[COLUMNS_DF_ALERTE].to_html(index=False, border=1)
    body = f"""
    <html>
        <body>
            <p>Bonjour,</p>
            <p>De nouvelles vulnérabilités ont été détectées pour vos produits suivis :</p>
            <br>
            {html_table}
            <br>
            <p><br>Consultez les bulletins complets sur le site de l'ANSSI.</p>
        </body>
    </html>
    """
    msg.attach(MIMEText(body, 'html'))
    nb_cve = len(df_filtered)

    try:
        # connexion au serveur SMTP     
        smtp_user = SMTP_USER if SMTP_USER else input("Email SMTP : ")
        smtp_password = SMTP_PASSWORD if SMTP_PASSWORD else getpass("Mot de passe application Gmail : ")
                
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        server.login(smtp_user, smtp_password)

        # Envoi du mail
        server.send_message(msg)
        log_validation(to_email, user_filtred_col, nb_cve, "Succès")
        print(f"Mail envoyé avec succès à {to_email}")

    except Exception as e:
        log_validation(to_email, user_filtred_col, nb_cve, "Échec")
        print(f"Erreur lors de l'envoi à {to_email}: {e}")

    finally:
        server.quit()


# Fonction principale pour exécuter le système d'alerte
def run_alert_system(df_scraped = NEW_DATA_FILE):
    df_new = pd.read_csv(df_scraped, dtype=str)
    
    if df_new.empty:
        print("Aucune nouvelle vulnérabilité détectée depuis le dernier scan.")
        return
    
    # Chargement de la base des abonnés
    if os.path.exists(USER_DB):
        with open(USER_DB, "r", encoding='utf-8') as f:
            users = json.load(f)

        # Envoi des alertes personnalisées
        for email, items in users.items():
            send_alert_email(email, items['colonne_cible'], items['filtres'], df_new)


###     Exemple d'utilisation   ###
# df_current = pd.read_csv(NEW_DATA_FILE, dtype=str)
# run_alert_system(NEW_DATA_FILE)

