# 🛡️ Dashboard de Veille Vulnérabilités (CVE Monitor)

Ce projet est une solution complète de veille en cybersécurité. Il automatise la collecte des alertes de sécurité publiées par le **CERT-FR**, les enrichit avec des données externes (Scores CVSS via MITRE, Scores EPSS via FIRST) et propose une interface de visualisation interactive pour explorer les menaces.

## 📋 Fonctionnalités

* **Collecte Automatisée :** Surveillance des flux RSS du CERT-FR et scraping des bulletins.
* **Enrichissement :** Ajout automatique des scores CVSS (Gravité) et EPSS (Probabilité d'exploitation) via APIs.
* **Dashboard Interactif :**
    * Filtrage temporel (Dernières 24h, 7 jours, historique complet).
    * Recherche par Éditeur (ex: Microsoft, Cisco, Adobe) ou Produit.
    * Filtrage par Score de criticité.
* **Visualisation :** KPIs dynamiques, graphiques de répartition par sévérité et timeline des alertes.

---

## 📂 Structure du Projet

Voici le rôle de chaque fichier pour comprendre le fonctionnement global :

| Fichier | Rôle | Description |
| :--- | :--- | :--- |
| **`pipeline.py`** | 📥 Collecte | **Le moteur du projet.** Il récupère les nouveaux bulletins, interroge les API (Mitre/First) et génère `data_brut.csv`. Il fonctionne en mode incrémental (ne traite que les nouveautés). |
| **`nettoyage_dataframe.py`** | 🧹 Nettoyage | **Le préparateur.** Il prend le fichier brut, nettoie les valeurs manquantes, formate les dates et produit `data_propre.csv` pour l'application. |
| **`app.py`** | 📊 Interface | **Le dashboard.** Application web réalisée avec Streamlit pour visualiser et filtrer les données nettoyées. |
| **`alerte.py`** | 📧 Notification | Script backend permettant l'envoi de mails d'alerte selon une configuration définie (exécuté indépendamment de l'interface). |
| **`config.py`** | ⚙️ Config | Contient les chemins de fichiers et les variables globales. |
| **`requirements.txt`** | 📦 Dépendances | Liste des librairies Python nécessaires. |

---

## 🚀 Installation

### 1. Prérequis
Assurez-vous d'avoir **Python 3.8+** installé sur votre machine.

### 2. Installation des librairies
Ouvrez un terminal à la racine du projet et exécutez :

```bash
pip install -r requirements.txt
