from getpass import getpass
from datetime import datetime
import smtplib
import json
import os
import pandas as pd
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart  
# Importation des paramètres de configuration
from config import SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, USER_DB, LAST_DATA_FILE, LOG_FILE


def log_validation(email, alert, nb_cve, status="Succès"):
    # Enregistrement ligne de validation dans un fichier texte.
    horodatage = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[{horodatage}] Envoi à : {email} | alerte : {alert} | CVE envoyées : {nb_cve} | Statut : {status}\n"
    
    # Mode 'a' pour 'append' (ajout à la fin du fichier sans effacer le reste)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg)


def get_new_vulnerabilities(df_current):
    return df_current 

    # Retourne les nouvelles lignes entre les deux scans. (DataFrame actuel et dernier scan enregistré)
    if not os.path.exists(LAST_DATA_FILE):
        return df_current # Si aucun fichier précédent
    
    df_last = pd.read_csv(LAST_DATA_FILE)
    
    # Identification des nouveautés par l'ID ANSSI et la CVE combinés (aucun doublon)
    new_entries = df_current[~df_current.set_index(['ID ANSSI', 'Identifiant CVE']).index.isin(
        df_last.set_index(['ID ANSSI', 'Identifiant CVE']).index
    )]
    return new_entries


def send_alert_email(to_email, user_filtred_col, user_filtred_items, df_new):
    # Filtrage selon les thèmes choisis par l'utilisateur [cite: 161]
    df_filtered = df_new[df_new[user_filtred_col].isin(user_filtred_items)]
    
    if df_filtered.empty: 
        return  # Rien à envoyer pour cet utilisateur
    
    # Construction du mail
    msg = MIMEMultipart()
    msg['From'] = "projet_python@esilv.fr"
    msg['To'] = to_email
    msg['Subject'] = "Alerte Sécurité : nouvelles vulnérabilités détectées"
    # Construction du corps du mail en HTML
    html_table = df_filtered[['Titre ANSSI', 'Identifiant CVE', 'Score CVSS', 'Base Severity', 'Éditeur/Vendor', "Produit"]].to_html(index=False, border=1)
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
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
        server.login(SMTP_USER, SMTP_PASSWORD)

        # Envoi du mail
        server.send_message(msg)
        log_validation(to_email, user_filtred_col, nb_cve, "Succès")
        print(f"Mail envoyé avec succès à {to_email}")

    except Exception as e:
        log_validation(to_email, user_filtred_col, nb_cve, "Échec")
        print(f"Erreur lors de l'envoi à {to_email}: {e}")

    finally:
        server.quit()


def run_alert_system(df_scraped):
    # Isolation des nouvelles entrées
    df_new = get_new_vulnerabilities(df_scraped)   
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

    # Mise à jour de l'historique pour éviter les doublons au prochain scan 
    df_scraped.to_csv(LAST_DATA_FILE, index=False)


# --- EXÉCUTION ---
df_resultat = pd.read_csv(LAST_DATA_FILE)  # Remplacer par le DataFrame final réel
run_alert_system(df_resultat)
