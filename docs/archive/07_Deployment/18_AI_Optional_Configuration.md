# AI Optional Configuration - MSAP

## Purpose
Kimi AI est une option post-analyse pour assister la redaction et l'interpretation. Elle est desactivee par defaut.

## Kubernetes configuration
Les cles API, endpoints et flags d'activation sont fournis via Kubernetes Secrets et values Helm. Aucun secret AI ne doit etre commite.

## Data flow
Evidence + scores + findings -> redaction/minimization -> optional Kimi AI -> draft text -> analyst validation. Aucun APK brut ni source decompilee complete n'est transmis.

## Security controls
Activation explicite, audit logs, timeouts, redaction obligatoire, validation humaine, pas de verdict malware garanti.

## Development mode
Docker Compose peut simuler la configuration AI pour developpement local, mais la validation de deploiement cible se fait sur Kubernetes.
