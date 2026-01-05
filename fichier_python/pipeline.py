

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
for elem in liste_lien:
    url = elem+"json/"
    response = requests.get(url)
    data = response.json()
    cves_du_bulletin = data['cves']
    # Cette étape sert à garder l'URL de l'alerte
    for cve in cves_du_bulletin:
        cve['source_alerte'] = elem
    ref_cves.extend(cves_du_bulletin)
print(ref_cves)

