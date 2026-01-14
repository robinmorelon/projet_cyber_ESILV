import feedparser
import requests
import pandas as pd
import time
import os


DATA_EXISTENTE = "data_brut.csv"
urls_deja_traitees = set()
df_existant = pd.DataFrame()
if os.path.exists(DATA_EXISTENTE):
    df_existant = pd.read_csv(DATA_EXISTENTE, dtype=str)
    if "source_alerte" in df_existant.columns:
        urls_deja_traitees = set(df_existant["source_alerte"].dropna().unique())
else:
    print("Pas de données existentes trouvées !")



# Créons une liste avec tous les liens
liste_lien = []
flux_RSS = ["https://www.cert.ssi.gouv.fr/alerte/feed/", "https://www.cert.ssi.gouv.fr/avis/feed/"]
for url in flux_RSS:
    rss_feed = feedparser.parse(url)
    liste_lien.extend([entry.link for entry in rss_feed.entries])
#print(liste_lien)

# Créons une liste avec toutes les CVE de chaque lien
#lien_test = 'https://www.cert.ssi.gouv.fr/avis/CERTFR-2025-AVI-1076/'
ref_cves = []
cve_unique = set()
for elem in liste_lien:
    if elem in urls_deja_traitees:
        continue
    url = elem+"json/"
    response = requests.get(url)
    data = response.json()
    #print(data)
    cves_du_bulletin = data['cves']
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
            risks = data.get("risks", [])
            if risks:
                new_line["description_alerte"] = risks[0].get("description", "Inconnu")
            else:
                new_line["description_alerte"] = "Non spécifié"
            ref_cves.append(new_line)
#print(ref_cves)
#print(len(cve_unique))


# Enrichissement avec les API
# Je crée des compteurs de tests pour voir le pourcentage de cve ou je n'ai pas pu récupérer les infos a cause du nom du chemin
#compteur_test_erreur_chemin_Mitre = 0
#compteur_test_erreur_globale = 0
info_api = {}
# je crée une variable temporaire pour voir ou j'en suis dans la boucle (uniquement pour la phase de test)
#tour_de_boucle = 0
for cve_id in cve_unique:
    #print(f"Tour de boucle numéro : {tour_de_boucle}")
    #tour_de_boucle+=1
    enrichissement_cve = {"cvss": None, "cvss_gravite": "Inconnu", "cvss_vecteur": "", "cwe_id": "Inconnu", "epss": None, "epss_percentile":None, "description_tech": "Inconnu"}
    try:
        url_mitre = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        requete_mitre = requests.get(url_mitre, timeout=5)
        if requete_mitre.status_code == 200:
            data_mitre = requete_mitre.json()
            try:
                metrics = data_mitre["containers"]["cna"]["metrics"][0]
                if "cvssV3_1" in metrics:
                    enrichissement_cve["cvss"] = metrics["cvssV3_1"]["baseScore"]
                    enrichissement_cve["cvss_gravite"] = metrics["cvssV3_1"]["baseSeverity"]
                    enrichissement_cve["cvss_vecteur"] = metrics["cvssV3_1"]["vectorString"]
                elif "cvssV3_0" in metrics:
                    enrichissement_cve["cvss"] = metrics["cvssV3_0"]["baseScore"]
                    enrichissement_cve["cvss_gravite"] = metrics["cvssV3_0"]["baseSeverity"]
                    enrichissement_cve["cvss_vecteur"] = metrics["cvssV3_0"]["vectorString"]
                else:
                    #compteur_test_erreur_chemin_Mitre+= 1
                    pass
                enrichissement_cve["description_tech"] = data_mitre["containers"]["cna"]["descriptions"][0]["value"]
                problem_types = data_mitre["containers"]["cna"].get("problemTypes", [])
                if problem_types:
                    enrichissement_cve["cwe_id"] = problem_types[0]["descriptions"][0].get("cweId", "Non disponible")
            except (KeyError, IndexError):
                pass
        elif requete_mitre.status_code == 429:
            print("API Mitre surchargée")
            time.sleep(10)
        url_first = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        requete_first = requests.get(url_first, timeout=5)
        if requete_first.status_code == 200:
            data_first = requete_first.json()
            if data_first.get("data"):
                enrichissement_cve["epss"] = float(data_first["data"][0]["epss"])
                enrichissement_cve["epss_percentile"] = float(data_first["data"][0]["percentile"])
        elif requete_first.status_code == 429:
            print("API First surchargée")
            time.sleep(10)
        time.sleep(1.5)
    except Exception as e:
        print(f"Erreur sur {cve_id} : {e}")
        #compteur_test_erreur_globale+=1
    info_api[cve_id] = enrichissement_cve

#On recolle les informations reçu dans ref_cves
for ligne in ref_cves:
    id_cve = ligne["name"]
    info = info_api.get(id_cve)
    if info:
        ligne["cvss"] = info["cvss"]
        ligne["cvss_gravite"] = info["cvss_gravite"]
        ligne["cvss_vecteur"] = info["cvss_vecteur"]
        ligne["cwe_id"] = info["cwe_id"]
        ligne["epss"] = info["epss"]
        ligne["epss_percentile"] = info["epss_percentile"]
        ligne["description_tech"] = info["description_tech"]




# Test pour dataframe pandas



if ref_cves:
    df_nouveau = pd.DataFrame(ref_cves)
    if not df_existant.empty:
        df_final = pd.concat([df_existant, df_nouveau], ignore_index=True)
    else:
        df_final = df_nouveau
else:
    df_final = df_existant


df_final.to_csv(DATA_EXISTENTE, index=False)


print(df_final.head())
#print(f"pourcentage d'erreur chemin : {compteur_test_erreur_chemin_Mitre/len(cve_unique)*100}")
#print(f"pourcentage d'erreur globale : {compteur_test_erreur_globale/len(cve_unique)*100}")



