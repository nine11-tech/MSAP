# AI Integration Decision - MSAP

## Decision
Kimi AI reste une extension optionnelle post-analyse. Le noyau MSAP reste deterministe: analyse statique Android, MASVS, ATT&CK Mobile prudent, preuves, scores et rapports.

## Cloud-native compatibility
L'option AI n'affecte pas la cible Kubernetes. Les secrets AI sont fournis via Kubernetes Secrets. L'activation est explicite par configuration Helm ou environnement.

## Data minimization
Kimi AI ne recoit pas d'APK brut, pas d'artefacts complets sensibles et pas de secrets non rediges. Le contexte est construit apres analyse a partir de findings, indicateurs, scores et preuves masquees.

## Allowed usage
Resumes executifs, reformulation de recommandations, clarification de findings MASVS, contextualisation prudente d'indicateurs ATT&CK Mobile et aide a la lisibilite du rapport.

## Forbidden usage
Classification malware garantie, generation d'exploit, analyse directe d'APK brut, remplacement des moteurs deterministes ou modification automatique des scores.
