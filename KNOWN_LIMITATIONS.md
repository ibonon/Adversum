# KNOWN LIMITATIONS — Vérification formelle Z3 (Adversum)

Document honnête de la portée réelle de la vérification Z3. À lire avant
toute présentation (jury hackathon, client) : il borne ce que le solveur
**prouve**, et ce qu'il **ne prouve pas**.

Dernière mise à jour : 2026-10-24

---

## 1. Contrat de conception (tranché explicitement)

**Z3 valide les findings positifs détectés par les règles statiques ; il ne
re-scanne pas le code pour détecter des faux négatifs de la regex.**

- La **détection** des opérations arithmétiques à risque appartient aux règles
  statiques (`modules/solidity/rules/arithmetic.py`, règle SOL-004).
- La **confirmation** mathématique appartient à Z3
  (`modules/formal_verification/z3_prover.py`) : pour une opération *déjà
  détectée*, Z3 prouve ou infirme qu'un débordement est *représentable*.

Le solveur n'est donc **pas** un filtre anti-faux-positif autonome, et il
**n'est pas** un détecteur de faux négatifs. La réduction des faux positifs
est assurée par d'autres couches (règles de garde SafeMath/pragma, validation
déterministe, raisonnement Nemotron, exécution d'exploit sur fork) — cf.
`README.md` et `BENCHMARK.md`.

Justification technique : le modèle Z3 porte sur **une opération arithmétique
isolée**. Prouver qu'une vulnérabilité est *atteignable* depuis l'extérieur
exigerait une analyse de reachability (points d'entrée, flot de contrôle,
état de stockage) que ce solveur ne fait pas — il ne peut donc pas, en l'état,
détecter des vulnérabilités manquées par la regex.

---

## 2. Ce que Z3 prouve réellement

1. **Représentabilité, pas accessibilité.** Pour une opération détectée, Z3
   prouve qu'il *existe* une paire de valeurs (dans la largeur de bits inférée)
   pour laquelle l'opération déborde. Il ne prouve pas qu'un attaquant peut
   atteindre cet état. Le champ `scope` de chaque résultat le rappelle :
   `"overflow representable for this operation (not reachability-proven)"`.

2. **SAT = contre-exemple concret.** En cas de SAT, le modèle Z3 fournit les
   valeurs numériques exactes des opérandes qui font déborder l'opération.

3. **UNSAT = la garde modélisée interdit le débordement.** Pour un contrat
   SafeMath ou `pragma >= 0.8.0`, le solveur retourne UNSAT : aucun débordement
   n'est possible *sous les contraintes modélisées*.

4. **Périmètre de règle limité.** Seule la règle SOL-004 (overflow/underflow)
   est adossée à Z3. Toutes les autres règles (reentrancy, access control,
   oracle, etc.) restent de la détection par motif, sans preuve formelle.

---

## 3. Ce que Z3 ne prouve PAS

1. **Pas de détection de faux négatifs.** Z3 ne parcourt pas le code à la
   recherche d'opérations non détectées par la regex.
2. **Pas de preuve d'accessibilité.** Voir §2.1.
3. **Sémantique de garde modélisée, pas extraite.** La protection SafeMath /
   `>= 0.8` est modélisée comme contrainte de non-débordement ; elle n'est pas
   vérifiée depuis le bytecode compilé.
4. **Largeurs mixtes.** La largeur de bits est inférée à partir de la
   déclaration de l'opérande gauche, puis droite. Une opération entre deux
   largeurs différentes n'est pas modélisée selon les règles de promotion de
   Solidity.

---

## 4. Limitation connue — le verdict UNSAT n'est pas contraignant

Lorsque Z3 retourne `UNSAT` (opération prouvée protégée) ou `UNPARSED`
(snippet non analysable), **le finding n'est pas retiré du rapport**. Le
verdict n'annote que le patch (`is_smt_verified`), pas la liste des findings.

Choix conservateur : mieux vaut sur-signaler un finding étiqueté
« règle statique seule » que le supprimer silencieusement. Conséquence : la
capacité de réfutation de Z3 existe mais n'est pas exploitée pour alléger le
rapport. C'est un axe d'évolution, pas un comportement caché.

---

## 5. La branche UNSAT est-elle atteignable en production ?

**Oui** — contrairement à une hypothèse initiale. Le contrôle de garde de la
règle regex est grossier (au niveau du fichier : `'SafeMath' in content and
'using SafeMath' in content`), tandis que celui du prover est différent
(`\bSafeMath\b`). Cette divergence fait que la regex peut émettre un finding
sur du code que le prover identifie comme protégé.

Preuve empirique (source `pragma ^0.4.24` avec bibliothèque SafeMath définie
mais sans `using SafeMath`) :

```
regex findings: 2
  verdict= UNPARSED guarded= True
  verdict= UNPARSED guarded= True
```

Le prover détecte bien la garde (`guarded=True`). Voir §4 : ce verdict n'est
actuellement pas utilisé pour retirer le finding.

---

## 6. Hypothèses implicites de `prove_overflow()` — état des tests (R2)

Chaque hypothèse est soit **couverte par un test** (`scripts/sandbox/verify_z3_assumptions.py`),
soit **documentée comme non couverte**.

| # | Hypothèse implicite | Statut | Preuve / risque |
|---|---|---|---|
| A1 | Les 3 opérateurs `+`, `-`, `*` sont traités pareil (R1.3 ne testait que `+`) | **Testé, OK** | `+` SAT, `-` SAT, `*` SAT |
| A2 | L'ordre des opérandes est respecté (asymétrie de `-`) | **Testé, OK** | `a=b-a` et `a=a-b` donnent des contre-exemples miroirs corrects |
| A3 | Une opération à plus de 2 opérandes (`a = a + b + c;`) | **Non couvert** | Seuls les 2 premiers opérandes sont modélisés (`c` ignoré) : contre-exemple potentiellement incomplet. Pas de faux négatif au niveau finding (la ligne reste détectée). |
| A4 | Largeurs mixtes (`uint8 s; uint256 b; s = s + b;`) | **Non couvert** | La largeur est inférée du **seul opérande gauche** → 8 bits ici, alors que Solidity promeut l'opération. Contre-exemple mal dimensionné possible. |
| A5 | Le modèle SAT respecte la largeur déclarée | **Testé, OK** | uint8 → valeurs ≤ 255 |
| A6 | La garde SafeMath/`using` est évaluée au niveau **fichier**, pas fonction | **Non couvert** | Un fichier contenant `using SafeMath` **quelque part** voit toute son arithmétique nue supprimée par la regex → **faux négatif de la regex**. Preuve : 0 finding sur un contrat où `a = a + x` (nu, unsafe en 0.4) cohabite avec `a = a.add(x)`. Z3, qui ne tourne que sur les findings émis, ne peut pas rattraper ce cas. |
| A7 | La forme composée (`a += b;`) équivaut à la forme binaire | **Testé, OK** | `a += b;` → SAT, opérateur `+` |
| A8 | Les bornes `require(var <= N)` sont appliquées au niveau **fichier** | **Non couvert** | `_extract_bounds()` scanne tout le fichier : un `require(x <= 200)` dans une fonction peut contraindre une opération sur un `x` homonyme d'une autre fonction. |

---

## 7. Le correctif `max(len(findings), len(patches_list))` — patch de surface

**Contexte.** Dans `modules/html_report/generator.py` :

```python
patches_list = (intelligence_data or {}).get("validated_patches", [])
smt_verified_count = sum(1 for pt in patches_list if pt.get("is_smt_verified"))
total_findings = max(len(findings), len(patches_list))
smt_verified_pct = (smt_verified_count / total_findings) * 100 if total_findings else 0.0
```

**Problème de fond.** Le numérateur et le dénominateur proviennent de **deux
populations différentes** :

- le numérateur compte des **patches** (`validated_patches`), construits depuis
  `all_findings[:10]` **avant** dédoublonnage ;
- le dénominateur (`findings`) est la liste **post-dédoublonnée** affichée dans
  le rapport.

`max()` empêche seulement le ratio de dépasser 100 % ; il ne réconcilie pas les
deux populations. Le pourcentage peut donc **sur-estimer** (ex. 10 patchs dont 5
correspondent à des findings supprimés par dédoublonnage → badge « 100 % des
findings prouvés » alors que la vraie proportion sur les findings affichés est
plus faible) ou **sous-estimer** (beaucoup de findings non arithmétiques vs 10
patchs).

**Risque de réapparition.** Tant que findings et patches ne partagent pas un
identifiant stable (qui survive au dédoublonnage), le biais reviendra sous une
autre forme (ex. badge par patch à la ligne 929 répétant le même pourcentage
global sur chaque carte, plutôt qu'un état par finding).

**Correctif de fond recommandé.** Calculer numérateur et dénominateur sur le
**même ensemble de findings** : marquer chaque finding d'un identifiant stable
avant dédoublonnage, propager cet identifiant dans le patch, puis compter
`{findings prouvés} / {findings affichés}`. Non implémenté ici (changement
multi-couches) — documenté explicitement.

---

## 8. Ancrage des hypothèses Nemotron avant Z3 — le numéro de ligne du modèle n'est pas fiable

**Nemotron identifie correctement la nature de l'opération vulnérable mais pas
toujours son numéro de ligne exact (non-déterminisme observé même à
`temperature=0.0`) ; le système recoupe donc chaque hypothèse avec une recherche
textuelle dans le fichier source avant de la soumettre à Z3, plutôt que de faire
confiance aveuglément à la position rapportée par le modèle.**

**Preuve empirique (run N2, appel réel NVIDIA NIM).** Sur la fixture
`overflow.sol` (opérations réelles en **lignes 10 et 14**), Nemotron a rapporté
les lignes **9 et 12**. Un run antérieur, sur le *même* prompt à
`temperature=0.0`, avait pourtant donné **10 et 14**. Sur `GuardedSafeMath.sol`,
Nemotron a rapporté la ligne **4** (`using SafeMath for uint256;`) pour
l'opération `c = a + b` située en réalité **ligne 2**. La nature de l'opération
(variable, opérateur, protection) était juste dans les deux cas.

**Mécanisme de recoupement** (`modules/solidity/overflow_anchor.py`) :

1. Pour chaque hypothèse `(variable, opération)`, recherche textuelle dans le
   **fichier source réel** des lignes contenant effectivement cette variable
   *et* cet opérateur (même logique de motif que
   `modules/solidity/rules/arithmetic.py`).
2. **Correspondance unique** → la ligne réelle est retenue comme ancrage pour
   `prove_overflow()` (le champ `line` du modèle est ignoré, seulement conservé
   pour comparaison sous `nemotron_line`). Le snippet transmis à Z3 est ensuite
   **isolé strictement** : la ligne est découpée sur les séparateurs
   d'instructions (`;{}`) pour ne garder que l'assignation arithmétique.
3. **Aucune correspondance ou plusieurs correspondances ambiguës** →
   hypothèse marquée `ANCRAGE_ECHOUE`, **non soumise à Z3**, et affichée comme
   hypothèse Nemotron non vérifiable — jamais de ligne devinée.

**Vérification** (`scripts/sandbox/verify_nemotron_anchor_n3.py`, sans appel
réseau) : malgré les numéros erronés (9/12/4), le recoupement retrouve bien
**10 / 14** et **2**, et marque correctement `ANCRAGE_ECHOUE` les cas sans
correspondance ou ambigus.

**Isolation du snippet (mesurée).** La ligne 2 de `GuardedSafeMath.sol` est une
bibliothèque déclarée sur une seule ligne :

```
library SafeMath { function add(uint a, uint b) internal pure returns (uint c) { c = a + b; require(c >= a); } }
```

L'ancrage en extrait le snippet `"c = a + b;"` (`snippet_isolated: true`) et non
la déclaration complète — ce qui le rend analysable par `_parse_arithmetic()`
alors que la ligne entière aurait produit `UNPARSED`. Les snippets obtenus pour
`overflow.sol` sont `"totalSupply = totalSupply + amount;"` (ligne 10) et
`"totalSupply = totalSupply - amount;"` (ligne 14).

**Limite résiduelle.** Si aucune assignation stricte n'est isolable sur la ligne
retenue (ou si une même ligne en contient plusieurs), l'hypothèse est rejetée
(`ANCRAGE_ECHOUE` en cas de pluralité) ou le snippet reste la ligne entière —
Z3 retourne alors `UNPARSED`, ce qui est un verdict honnête et non un échec
silencieux.

---

## 9. Cas particulier — la bibliothèque SafeMath **est** la garde de ses appelants

**Point de sémantique à ne pas confondre.** Le code interne de `SafeMath`
contient littéralement l'opération non protégée (`c = a + b;`) : c'est
précisément ce code qui *implémente* le revert sur débordement. La bibliothèque
ne doit donc **pas** être signalée comme vulnérable pour son propre compte :
c'est elle qui protège les autres contrats.

**Ce que le pipeline retourne réellement** (fixture `GuardedSafeMath.sol`,
`library SafeMath { ... c = a + b; require(c >= a); }` ligne 2) — verdicts
mesurés par `scripts/sandbox/verify_nemotron_z3_n3.py` :

```
snippet isolé : 'c = a + b;'
[prove_overflow, guarded=False] verdict=SAT   exploitable=True
    contre-exemple : {'a': 115792089237316195423570985005764904578608178829233194374025017968601264553977,
                      'b': 115792089237316188995818807972726805685421615300990153950645608876741788434425}
[prove_overflow, guarded=True ] verdict=UNSAT exploitable=False
```

Interprétation :

- **Snippet isolé seul** → `SAT`. Un fragment `c = a + b;` pris hors de tout
  contexte est bien une addition 256 bits qui peut déborder. C'est la raison
  pour laquelle on **ne soumet jamais le snippet nu** au pipeline de rapport.
- **Avec la garde détectée au niveau du fichier** (`_detect_guard()` voit
  `SafeMath` dans le source) → `UNSAT`. La sémantique modélisée de la garde
  interdit le débordement : le contrat est protégé.

**Conséquence dans le pipeline `/audit`.** La détection de garde est
aujourd'hui **au niveau du fichier**, pas de la fonction : tout fichier qui
importe/`using SafeMath` voit son arithmétique nue considérée comme protégée.
Pour la *bibliothèque elle-même*, le résultat est correct (UNSAT → non
exploitable) mais il repose sur une heuristique textuelle, pas sur une
différentiation « code de la garde » vs « code gardé ». C'est la même limite que
§5/A6 : un contrat 0.4 où l'addition nue `a = a + x` cohabiterait avec
`a = a.add(x)` verrait, à tort, l'addition nue protégée. Corriger ce point
exigerait une analyse par fonction (ou par portée `using`), hors périmètre
actuel.

---
