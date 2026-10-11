# 🚀 Guide de Déploiement — Nebius AI Cloud & Token Factory

Ce guide décrit la procédure officielle pour déployer **Adversum** sur l'infrastructure **Nebius AI Cloud** dans le cadre du **Nebius x NVIDIA Global AI Hackathon**.

---

## 🏗️ Architecture de Déploiement

```
                              ┌──────────────────────────────────────────────┐
                              │           NEBIUS AI CLOUD                    │
                              │                                              │
[Utilisateur / Juge]          │   ┌──────────────────────────────────────┐   │
        │                     │   │ Nebius Load Balancer (IP Publique)   │   │
        │ HTTPS (Port 80/443) │   └──────────────────┬───────────────────┘   │
        ▼                     │                      │                       │
┌───────────────────────────┐ │         ┌────────────┴────────────┐          │
│ Dashboard Frontend (Vite) │ ◄─────────┤ Nginx Reverse Proxy     │          │
└─────────────┬─────────────┘ │         └────────────┬────────────┘          │
              │               │                      │                       │
              │ /api/*        │         ┌────────────▼────────────┐          │
              └───────────────┼────────►│ FastAPI Backend         │          │
                              │         │ (Moteur SAST Rust Core) │          │
                              │         └────────────┬────────────┘          │
                              │                      │                       │
                              └──────────────────────┼───────────────────────┘
                                                     │
                                                     │ Inférence IA
                                                     ▼
                              ┌──────────────────────────────────────────────┐
                              │ Nebius Token Factory                         │
                              │ Modèle : nvidia/Nemotron-3_5-Lightning       │
                              │ Endpoint : api.tokenfactory.nebius.com/v1/   │
                              └──────────────────────────────────────────────┘
```

---

## 📋 Prérequis

1. **Compte Nebius AI Cloud** actif ([console.nebius.ai](https://console.nebius.ai))
2. **Clé API Nebius Token Factory** configurée :
   ```bash
   export NEBIUS_API_KEY="votre_cle_nebius_ici"
   ```
3. **Nebius CLI (`nebius`)** installée sur votre machine ou instance :
   ```bash
   curl -sSL https://storage.nemax.nebius.cloud/cli/install.sh | bash
   nebius init
   ```
4. **Docker** & **Docker Compose** (version >= 2.20)

---

## ⚡ Méthode 1 : Déploiement Rapide sur Nebius Compute (Recommandé pour Démo)

Cette méthode déploie l'intégralité de la stack (Backend Rust/FastAPI + Frontend Vite + Postgres + Redis) sur une instance virtuelle **Nebius Compute** en moins de 5 minutes.

### 1. Provisionner une instance Nebius Compute

Depuis la console Nebius ou via la CLI :

```bash
nebius compute instance create \
  --name adversum-demo-node \
  --platform standard-v3 \
  --cores 4 \
  --memory 16GB \
  --image-family ubuntu-2204-lts \
  --disk-size 50GB \
  --public-ip \
  --ssh-key-path ~/.ssh/id_rsa.pub
```

### 2. Se connecter et cloner le dépôt

```bash
ssh ubuntu@<IP_PUBLIQUE_NEBIUS>

# Installer Docker & Git
sudo apt-get update && sudo apt-get install -y git docker.io docker-compose-v2
sudo usermod -aG docker $USER
newgrp docker

# Cloner Adversum
git clone https://github.com/ibonon/Adversum.git
cd Adversum
```

### 3. Configurer l'environnement de production

Créez le fichier `.env` sur le serveur :

```bash
cat << 'EOF' > .env
# --- Sécurité API ---
API_KEY=adv-dev-key-123
ALLOWED_ORIGINS=http://localhost:3000,http://<IP_PUBLIQUE_NEBIUS>,https://<DOMAINE_DEMO>

# --- Nebius Token Factory (NVIDIA Nemotron) ---
NEBIUS_API_KEY=votre_cle_nebius_ici
NEBIUS_BASE_URL=https://api.tokenfactory.nebius.com/v1/
NEBIUS_MODEL=nvidia/Nemotron-3_5-Lightning

# --- Tavily Threat Intelligence (Bonus $3,000) ---
TAVILY_API_KEY=votre_cle_tavily_ici
EOF
```

### 4. Lancer les conteneurs

```bash
# Build et démarrage en arrière-plan
docker compose up -d --build

# Vérifier la santé des services
docker compose ps
curl http://localhost:8000/health
```

Accédez immédiatement au dashboard sur : `http://<IP_PUBLIQUE_NEBIUS>:3000`

---

## ☸️ Méthode 2 : Déploiement Kubernetes sur Nebius Managed K8s (MK8s)

Pour un déploiement institutionnel haute disponibilité avec mise à l'échelle automatique.

### 1. Authentification au Container Registry Nebius

```bash
nebius cr registry create --name adversum-registry
nebius cr login

export REGISTRY="cr.nemax.nebius.cloud/adversum"
```

### 2. Build et publication des images

```bash
# Backend (Rust core + FastAPI)
docker build -t $REGISTRY/adversum-backend:latest -f Dockerfile.backend .
docker push $REGISTRY/adversum-backend:latest

# Frontend (Vite + Nginx)
docker build -t $REGISTRY/adversum-frontend:latest -f frontend/Dockerfile .
docker push $REGISTRY/adversum-frontend:latest

# Scanner isolé
docker build -t $REGISTRY/adversum-scanner:latest -f Dockerfile.scanner .
docker push $REGISTRY/adversum-scanner:latest
```

### 3. Déploiement sur le cluster

```bash
# Appliquer le manifest officiel Nebius
kubectl apply -f deploy/nebius/k8s-adversum.yaml

# Injecter votre clé API Nebius en secret Kubernetes
kubectl create secret generic adversum-secrets \
  --namespace adversum \
  --from-literal=NEBIUS_API_KEY="votre_cle_nebius_ici" \
  --from-literal=TAVILY_API_KEY="votre_cle_tavily_ici" \
  --from-literal=API_KEY="adv-dev-key-123" \
  --dry-run=client -o yaml | kubectl apply -f -
```

### 4. Récupérer l'adresse IP publique

```bash
kubectl get svc adversum-frontend-lb -n adversum -w
```

Nebius Network Load Balancer assigne une adresse IP publique externe routable pour la démo des juges.

---

## 🧪 Validation & Tests en Direct

Pour vérifier que l'infrastructure tourne avec succès sur NVIDIA Nemotron via Nebius :

### Test de connectivité IA :
```bash
curl -X GET "http://localhost:8000/health"
```
Réponse attendue :
```json
{"status": "ok"}
```

### Lancement d'un scan complet de démonstration :
```bash
curl -X POST "http://localhost:8000/api/v1/scan/clone-and-scan" \
  -H "X-API-Key: adv-dev-key-123" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/ibonon/Adversum.git",
    "project_name": "Demo Target",
    "format": "json"
  }'
```

Le résultat contiendra le bloc certifié :
```json
"ai_metadata": {
  "nebius_enabled": true,
  "model": "nvidia/Nemotron-3_5-Lightning",
  "infrastructure": "Nebius Token Factory"
}
```

---

## 🔧 Dépannage (Troubleshooting)

| Symptôme | Cause probable | Solution |
| :--- | :--- | :--- |
| `504 Gateway Timeout` | Scan d'un repo volumineux | Les timeouts proxy Nginx et FastAPI sont configurés à 900s par défaut. |
| `AI validation mock fallback` | `NEBIUS_API_KEY` absente ou invalide | Vérifiez que la variable est exportée dans `.env` ou dans le secret K8s. |
| `Docker socket permission denied` | Utilisateur non dans le groupe docker | Exécutez `sudo usermod -aG docker $USER` sur l'hôte Nebius. |
