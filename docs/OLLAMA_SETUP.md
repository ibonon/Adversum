# Configuration Ollama - LLM Open Source Local

## 🎯 Pourquoi Ollama ?

Ollama permet d'utiliser un **LLM open source puissant localement** pour la rédaction des rapports d'audit, sans dépendre d'API externes payantes.

### Avantages

- ✅ **Gratuit** : Pas de coût par requête
- ✅ **Local** : Vos données restent sur votre machine
- ✅ **Confidentialité** : Aucun envoi de code à des services tiers
- ✅ **Performant** : Modèles optimisés pour la rédaction
- ✅ **Open Source** : Contrôle total

---

## 📦 Installation d'Ollama

### Windows

1. **Télécharger Ollama** :
   - Aller sur https://ollama.ai/download
   - Télécharger l'installateur Windows
   - Exécuter l'installateur

2. **Vérifier l'installation** :
   ```powershell
   ollama --version
   ```

### Linux / macOS

```bash
# Installation via curl
curl -fsSL https://ollama.ai/install.sh | sh
```

---

## 🤖 Télécharger un Modèle

Ollama supporte de nombreux modèles open source. Pour la rédaction de rapports, nous recommandons :

### Modèles Recommandés

#### 1. **Llama 3** (Recommandé)
```bash
ollama pull llama3
```
- **Taille** : ~4.7 GB
- **Qualité** : Excellente pour la rédaction
- **Performance** : Rapide

#### 2. **Mistral** (Alternative)
```bash
ollama pull mistral
```
- **Taille** : ~4.1 GB
- **Qualité** : Très bonne
- **Performance** : Très rapide

#### 3. **Codestral** (Spécialisé Code)
```bash
ollama pull codestral
```
- **Taille** : ~7 GB
- **Qualité** : Excellente pour le code
- **Performance** : Rapide

#### 4. **DeepSeek R1:7B** (Raisonnement Avancé)
```bash
ollama pull deepseek-r1:7b
```
- **Taille** : ~4.7 GB
- **Qualité** : Exceptionnelle pour le raisonnement de sécurité (Distilled from R1)
- **Performance** : Rapide

#### 5. **DeepSeek Coder** (Spécialisé Code)
```bash
ollama pull deepseek-coder
```
- **Taille** : ~3.8 GB
- **Qualité** : Très bonne pour le code
- **Performance** : Très rapide

#### 6. **DeepSeek V3:7B** (Lite / Distilled)
```bash
ollama pull deepseek-v3:distill-qwen-7b
```
- **Taille** : ~4.7 GB
- **Qualité** : Excellente (raisonnement DeepSeek V3 dans un format léger)
- **Performance** : Rapide

#### 7. **Qwen** (Multilingue)
```bash
ollama pull qwen
```
- **Taille** : ~4.4 GB
- **Qualité** : Excellente
- **Performance** : Rapide


### Vérifier les Modèles Installés

```bash
ollama list
```

---

## ⚙️ Configuration dans Adversum

### Configuration par Variables d'Environnement

Créer un fichier `.env` à la racine du projet :

```env
# Ollama (LLM open source local) - RECOMMANDÉ
USE_OLLAMA=true
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3

# Optionnel: Désactiver les API cloud
# OPENAI_API_KEY=
# ANTHROPIC_API_KEY=
```

### Configuration Automatique

Par défaut, Adversum utilise Ollama si disponible. Aucune configuration supplémentaire n'est nécessaire si :
- Ollama est installé
- Un modèle est téléchargé (ex: `llama3`)
- Ollama tourne sur `http://localhost:11434`

---

## 🚀 Utilisation

### Démarrer Ollama

Ollama démarre automatiquement en arrière-plan après l'installation. Si besoin :

```bash
# Windows (démarre automatiquement)
# Linux/macOS
ollama serve
```

### Démarrer Adversum

```bash
cd adversum/api
uvicorn main:app --reload
```

Adversum utilisera automatiquement Ollama pour la rédaction des rapports.

---

## 🔧 Options Avancées

### Changer le Modèle

```env
OLLAMA_MODEL=mistral  # Au lieu de llama3
```

### Changer l'URL d'Ollama

Si Ollama tourne sur un autre serveur :

```env
OLLAMA_BASE_URL=http://192.168.1.100:11434
```

### Désactiver Ollama (Utiliser API Cloud)

```env
USE_OLLAMA=false
OPENAI_API_KEY=sk-...
# ou
ANTHROPIC_API_KEY=sk-...
```

### Utiliser Ollama + API Cloud (Fallback)

Si Ollama n'est pas disponible, le système peut fallback vers les API cloud :

```env
USE_OLLAMA=true
OLLAMA_MODEL=llama3
OPENAI_API_KEY=sk-...  # Fallback si Ollama échoue
```

---

## 📊 Comparaison des Modèles

| Modèle | Taille | Qualité Rédaction | Vitesse | RAM Min |
|--------|--------|-------------------|---------|---------|
| **llama3** | 4.7 GB | ⭐⭐⭐⭐⭐ | ⚡⚡⚡ | 8 GB |
| **mistral** | 4.1 GB | ⭐⭐⭐⭐ | ⚡⚡⚡⚡ | 8 GB |
| **deepseek-r1:7b** | 4.7 GB | ⭐⭐⭐⭐⭐+ | ⚡⚡⚡ | 8 GB |
| **codestral** | 7 GB | ⭐⭐⭐⭐⭐ | ⚡⚡⚡ | 16 GB |
| **deepseek-coder** | 3.8 GB | ⭐⭐⭐⭐ | ⚡⚡⚡⚡ | 8 GB |
| **deepseek-v3:7b** | 4.7 GB | ⭐⭐⭐⭐⭐ | ⚡⚡⚡ | 8 GB |
| **qwen** | 4.4 GB | ⭐⭐⭐⭐⭐ | ⚡⚡⚡ | 8 GB |


---

## 🧪 Test

### Test Ollama Directement

```bash
ollama run llama3 "Rédige un résumé d'audit de sécurité en 2 paragraphes."
```

### Test via Adversum

1. Démarrer l'API :
   ```bash
   cd adversum/api
   uvicorn main:app --reload
   ```

2. Soumettre un audit :
   ```bash
   curl -X POST http://localhost:8000/audit \
     -H "X-API-Key: adv-dev-key-123" \
     -H "Content-Type: application/json" \
     -d '{"target_path": "F:\\Adversum\\adversum"}'
   ```

3. Vérifier les logs :
   ```
   INFO: Ollama disponible sur http://localhost:11434. Modèles: ['llama3']
   INFO: Génération du rapport d'audit pour X findings (LLM pour rédaction uniquement)...
   ```

---

## 🐛 Dépannage

### Ollama non détecté

**Problème** : `Ollama non disponible sur http://localhost:11434`

**Solutions** :
1. Vérifier qu'Ollama est installé : `ollama --version`
2. Vérifier qu'Ollama tourne : `ollama list`
3. Vérifier le port : `netstat -ano | findstr :11434` (Windows)

### Modèle non trouvé

**Problème** : `Model 'llama3' not found`

**Solution** :
```bash
ollama pull llama3
```

### Performance lente

**Solutions** :
1. Utiliser un modèle plus petit (mistral, deepseek-coder)
2. Réduire la taille du contexte
3. Utiliser un GPU si disponible

### Erreur de connexion

**Problème** : `Connection refused`

**Solutions** :
1. Vérifier que Ollama tourne : `ollama serve`
2. Vérifier l'URL : `OLLAMA_BASE_URL=http://localhost:11434`
3. Vérifier le firewall

---

## 💡 Recommandations

### Pour la Production

1. **Modèle** : `llama3` ou `mistral` (bon équilibre qualité/performance)
2. **RAM** : Minimum 8 GB disponible
3. **GPU** : Optionnel mais recommandé (NVIDIA CUDA)
4. **Monitoring** : Surveiller l'utilisation mémoire

### Pour le Développement

1. **Modèle** : `mistral` (plus rapide, plus léger)
2. **RAM** : 8 GB suffisant
3. **GPU** : Non nécessaire

---

## 📚 Ressources

- **Site Ollama** : https://ollama.ai
- **Modèles disponibles** : https://ollama.ai/library
- **Documentation** : https://github.com/ollama/ollama
- **API** : https://github.com/ollama/ollama/blob/main/docs/api.md

---

## ✅ Checklist

- [ ] Ollama installé
- [ ] Modèle téléchargé (`ollama pull llama3`)
- [ ] Ollama accessible (`ollama list`)
- [ ] Variables d'environnement configurées (optionnel)
- [ ] Test réussi (`ollama run llama3 "test"`)

---

*Dernière mise à jour : 2025-01-27*
