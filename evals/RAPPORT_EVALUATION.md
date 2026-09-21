# Rapport de résultats d'évaluation — SecureRAG

## Méthodologie

Le dataset d'évaluation compte **24 cas** :
- **20 cas ancrés sur de vraies CVE**, échantillonnées directement du corpus Pinecone en production (via 12 requêtes couvrant des classes de vulnérabilités variées : injection SQL, RCE, XSS, contournement d'authentification, déni de service, etc.). Pour chaque CVE, un scénario d'incident SOC réaliste a été généré par Claude à partir de la description technique — sans jamais nommer l'identifiant CVE ni copier le texte source verbatim — afin de garantir une vérité terrain fiable sans donner d'indice trivial à l'agent.
- **4 cas "pièges"** : incidents bénins (lenteur d'un service, erreur de routine, pic de charge planifié) ne correspondant à aucune vraie vulnérabilité, pour vérifier que l'agent sait s'abstenir plutôt qu'inventer une réponse.

Chaque cas est passé dans l'agent LangGraph complet (analyse → recherche CVE → recherche logs → synthèse), avec mesure automatique de 6 métriques.

## Résultats

| Métrique | Résultat | Définition |
|---|---|---|
| Précision de récupération (top-k) | **90 %** (18/20) | Proportion de cas où la CVE attendue figure dans les résultats retournés par la recherche Pinecone |
| Taux de hallucination | **0 %** (0/24) | Proportion de cas où l'agent cite une CVE qu'il n'a jamais réellement récupérée via la recherche |
| Cohérence de sévérité | **80 %** (16/20) | Proportion de cas où la sévérité prédite correspond à la sévérité CVSS réelle de la CVE identifiée |
| Taux de succès sur les pièges | **100 %** (4/4) | Proportion de cas pièges où l'agent renvoie correctement une liste de CVE vide plutôt que d'inventer |
| Latence moyenne | **24,2 s** | Temps de traitement de bout en bout par incident |
| Latence p95 | **27,7 s** | 95e percentile de la latence |
| Coût moyen par requête | **~0,006 $** (estimation) | Estimation grossière par comptage de caractères — voir limite ci-dessous |

## Itération mesurée : correction du biais de sévérité

Un premier run a révélé une cohérence de sévérité de seulement **40 %**, avec un biais systématique de surestimation (l'agent prédisait presque toujours une sévérité égale ou supérieure à l'attendu, jamais inférieure). Investigation : le prompt de synthèse demandait d'évaluer la sévérité à partir du ton de la description d'incident, sans ancrage explicite sur la sévérité CVSS déjà disponible dans les résultats de recherche.

**Correction** : le prompt a été modifié pour exiger l'alignement de la sévérité prédite sur le CVSS de la CVE identifiée, sauf preuve concrète d'aggravation objective (compromission confirmée, exfiltration avérée) — pas simplement une description qui "sonne grave".

**Résultat** : cohérence de sévérité passée de 40 % à **80 %**, sans dégradation des autres métriques (précision de récupération et taux de hallucination inchangés à 90 % et 0 %).

## Limites connues

- **Corpus non exhaustif** : ~3200 CVE (mélange historique + publications 2026 récentes), sur les 378 000+ CVE que compte la NVD. La précision de récupération est mesurée sur ce périmètre, pas sur l'exhaustivité de la base NVD.
- **Coût approximatif** : l'estimation de coût utilise une heuristique grossière (nombre de caractères ÷ 4 ≈ nombre de tokens), pas les `usage_metadata` exacts de chaque appel LLM. Une mesure précise nécessiterait d'instrumenter chaque appel individuellement.
- **Dataset généré, pas un jeu de test indépendant** : les scénarios d'incident sont générés par le même modèle (Claude) que celui utilisé par l'agent, ce qui peut introduire une corrélation de style entre génération et évaluation. Un jeu de test rédigé manuellement ou par un tiers renforcerait la validité de la mesure.
- **Échantillon relativement restreint** (24 cas) : suffisant pour détecter et corriger un biais grossier (comme celui de sévérité), mais les taux mesurés (90 %, 80 %...) ont une marge d'incertitude statistique non négligeable à ce volume.
