# RAVEN

Reconnaissance & API Vulnerability Enumeration Navigator.

RAVEN est un assistant local pour reconnaissance Bug Bounty autorisee. Il impose un scope, limite le bruit, refuse les cibles hors scope et produit des preuves reproductibles dans `results/<project>/`.

## Installation Kali

```bash
sudo apt update
sudo apt install -y seclists payloadsallthethings
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Scope

Copiez `config/scope.example.yaml` vers `config/scope.yaml`, puis adaptez :

- `allowed_domains`
- `allowed_urls`
- `deny`
- `headers`
- `rate_limit`
- `proxy`

RAVEN refuse tout scan sans scope et bloque automatiquement les domaines hors scope.

## SecLists et wordlists

```bash
python3 main.py wordlists
```

RAVEN detecte SecLists dans :

- `/usr/share/seclists`
- `/usr/share/wordlists/seclists`
- `/opt/SecLists`

Si SecLists est absent, RAVEN utilise les wordlists locales `wordlists/small.txt` et `wordlists/api.txt`.

## Exploit-DB Intelligence

Installation Kali :

```bash
sudo apt update
sudo apt install -y exploitdb
searchsploit -u
```

Commandes :

```bash
python3 main.py exploitdb --status
python3 main.py exploitdb --search-tech keycloak --limit 5
python3 main.py exploitdb --search-cve CVE-2023-XXXXX
python3 main.py exploitdb --class xss --limit 10
```

RAVEN utilise Exploit-DB/SearchSploit en mode local et passif pour prioriser les validations manuelles :

- aucun exploit n'est execute ;
- aucun PoC n'est telecharge depuis Internet ;
- aucun payload agressif n'est genere automatiquement ;
- le mode `metadata_only` est actif par defaut ;
- les PoC locaux doivent etre lus et valides manuellement uniquement dans un cadre autorise.

## Profils de bruit

Le profil par defaut est `quiet`.

```bash
python3 main.py fuzz \
  --scope config/scope.yaml \
  --target https://example.com/FUZZ \
  --profile quiet
```

Profils disponibles :

- `quiet` : 1 req/s, 1 thread, timeout 12
- `balanced` : 2 req/s, 3 threads, timeout 10
- `deep` : 5 req/s, 5 threads, timeout 8, exige `--confirm-deep`

RAVEN ralentit ou met en pause si des signaux 403, 429, 503, timeouts ou WAF/CDN apparaissent. Il ne tente jamais de contourner Cloudflare, DataDome, Akamai, CloudFront, Fastly ou autres protections.

## Commandes utiles

```bash
python3 main.py init --project example
python3 main.py doctor
python3 main.py scan --scope config/scope.yaml --profile passive
python3 main.py scan --scope config/scope.yaml --target https://example.com --profile active-safe
python3 main.py recon --scope config/scope.yaml --profile passive
python3 main.py crawl --scope config/scope.yaml --target https://example.com --depth 2 --profile passive
python3 main.py js --scope config/scope.yaml --target https://example.com --profile passive
```

Profils CLI modernes :

- `passive` : reconnaissance douce, faible concurrence, pas de fuzzing bruyant.
- `balanced` : ajoute de la discovery controlee avec calibration.
- `active-safe` : scan reseau plus pousse mais controle : crawl, JS, discovery calibree, API/CORS/OAuth/GraphQL safe, analyse formulaires, param-mining leger et payloads safe limites.

Les anciens profils `quiet`, `balanced`, `deep` restent acceptes pour compatibilite.

Chaque nouveau run actif cree un dossier :

```text
results/<run_id>/
  raven.log
  requests.jsonl
  endpoints.jsonl
  js_files/
  js_files.jsonl
  js_endpoints.jsonl
  active_findings.jsonl
  findings.json
  reports/report.md
  reports/report.json
```

Fuzzing controle avec calibration active par defaut :

```bash
python3 main.py fuzz \
  --scope config/scope.yaml \
  --target https://example.com/FUZZ \
  --profile passive
```

Alias plus lisible :

```bash
python3 main.py discover \
  --scope config/scope.yaml \
  --target https://example.com/FUZZ \
  --profile passive
```

Options utiles :

```bash
python3 main.py fuzz \
  --scope config/scope.yaml \
  --target https://example.com/FUZZ \
  --match-status 200,204,301,302,307,308,401 \
  --filter-status 403,404 \
  --filter-size 1830 \
  --filter-regex "not found" \
  --no-calibration \
  --ignore-baseline
```

XSS reflection checker non agressif :

```bash
python3 main.py xss \
  --scope config/scope.yaml \
  --target "https://example.com/search?q=FUZZ" \
  --profile quiet
```

IDOR/BOLA lecture seule avec deux comptes autorises :

```bash
python3 main.py idor \
  --scope config/scope.yaml \
  --endpoints results/project/api_endpoints.txt \
  --token-a TOKEN_A \
  --token-b TOKEN_B \
  --profile quiet
```

Rapport :

```bash
python3 main.py report --run-id <run_id> --format markdown
python3 main.py show --run-id <run_id>
python3 main.py findings --run-id <run_id> --severity medium
python3 main.py endpoints --run-id <run_id> --type api
python3 main.py export --run-id <run_id> --format markdown
python3 main.py resume --run-id <run_id>
```

Scan actif safe sur les endpoints deja collectes :

```bash
python3 main.py scan \
  --scope config/scope.yaml \
  --target https://example.com \
  --profile active-safe
```

Ou en deux etapes, sur les endpoints deja collectes :

```bash
python3 main.py active \
  --input results/<run_id>/endpoints.jsonl \
  --payload-profile safe
```

Le moteur actif safe utilise uniquement des marqueurs non destructifs : reflection marker, open redirect sur parametres cibles, erreurs SQL basiques sans time-based, SSTI basique, path traversal indicatif, type confusion JSON limitee. Il respecte le scope, les chemins interdits et les methodes autorisees.

Pour autoriser les checks POST safe, le scope doit explicitement contenir `POST` dans `allowed_methods`. PUT/PATCH/DELETE restent desactives par defaut.

Apres installation comme console script, l'objectif est :

```bash
raven fuzz --scope config/scope.yaml --target https://example.com/FUZZ
```

## Burp Suite

Activez le proxy dans `config/scope.yaml` :

```yaml
proxy:
  enabled: true
  url: "http://127.0.0.1:8080"
```

Les commandes `curl` reproductibles sont sauvegardees dans les findings et dans le rapport.

## Resultats

RAVEN ecrit dans `results/<project>/` :

- `urls.txt`
- `live_hosts.txt`
- `js_files.txt`
- `js_endpoints.txt`
- `api_endpoints.txt`
- `fuzz_results.json`
- `filtered_noise.json`
- `baselines/fuzz_baseline.json`
- `idor_matrix.json`
- `idor_matrix.md`
- `xss_reflections.json`
- `findings.json`
- `findings.md`
- `reports/report.md`
- `endpoints.jsonl`
- `raw/http_results.jsonl`
- `raven.sqlite3`

Les commandes `show`, `findings`, `endpoints` et `export` relisent ces fichiers locaux et ne lancent aucune requete reseau.

## Limites de securite

RAVEN ne fait pas de DDoS, bruteforce, credential stuffing, OTP bypass, password guessing, spam, exploitation destructive, bypass WAF/anti-bot ou execution JavaScript navigateur. Les modules actifs sont concus pour produire des candidats a verifier manuellement dans Burp Suite, uniquement sur des programmes autorises.

## Interpreter les findings

- `info` : observation utile, pas une vulnerabilite confirmee.
- `low` : signal faible ou non destructif a verifier.
- `medium` : comportement interessant avec preuve technique, validation manuelle requise.
- `high/critical` : RAVEN ne les attribue pas automatiquement sans preuve forte.

Les secrets sont toujours masques dans les logs, rapports et preuves.

## Ajouter un module

Ajoutez un fichier dans `modules/`, exposez une fonction `run_<module>(context)`, puis connectez-la dans `main.py`. Le `context` contient `project`, `target`, `scope`, `config`, `http_client`, `storage`, `logger`, `rate_limiter`, `noise_guard` et `profile`.
