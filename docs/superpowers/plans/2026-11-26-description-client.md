# Description d'un client — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** une description libre (documentation admin) par client `SERVER_CLIENT`, saisie et lue dans la page Clients.

**Architecture :** clé facultative `DESCRIPTION` traitée exactement comme `DEPLOYMENT_GROUP` dans
`lib/st_mesh_group_ops.py` (validation, écriture du formulaire, classement « sans reconnexion » via
`METADATA_CLIENT_KEYS`), puis un champ et une colonne dans `lib/webui/templates/client_config.html`.

**Tech Stack :** Python 3 (Flask, toml), gabarit Jinja + JS sans framework (bootstrap-table), pytest.

**Spec :** `docs/superpowers/specs/2026-11-26-description-client-design.md`

## Global Constraints

- Clé `DESCRIPTION`, texte multiligne, **500 caractères au plus après `strip()`** ; 501 → erreur de champ 400, pas de troncature.
- Texte vide → clé retirée du client.
- Appel sans `DESCRIPTION` → valeur existante conservée.
- Changer seulement la description ne reconnecte aucune sonde (`affected_clients == []`) et n'entre pas dans la config générée des sondes.
- Tout texte affiché passe par `st.esc` ; tout nouveau texte d'interface a sa traduction dans `lib/webui/static/i18n/fr.json`.
- Le hook `.githooks/pre-commit` incrémente la version à chaque commit : ne pas le contourner.
- L'arbre de travail contient des modifications sans rapport (`live_map.html`, une partie de `fr.json`, le message
  de `lib/st_mesh.py:952`) : ne les inclure dans aucun commit de ce plan ; pour `fr.json`, n'indexer que les deux
  lignes ajoutées ici (patch réduit à ces lignes puis `git apply --cached`, `git add -p` étant interactif).

## Review Focus

1. Description avec `<script>`, guillemets ou apostrophes : affichée littéralement dans la colonne et l'infobulle (échappement `st.esc`, qui gère `"` et `'`). — vérification manuelle Tâche 2.
2. Description multiligne (retours `\n`, lignes Windows `\r\n`) : conservée à l'identique dans le TOML et relue telle quelle. — test Tâche 1.
3. Description d'exactement 500 caractères avec espaces autour : acceptée, enregistrée sans les espaces. — test Tâche 1.
4. Caractères non ASCII (accents, émojis) : comptés en caractères, pas en octets ; relus intacts du TOML. — test Tâche 1.
5. Description trop longue écrite à la main dans le TOML : `_validate_clients` refuse alors toute modification de client (422). Comportement accepté, identique à `DEPLOYMENT_GROUP` ; pas de test.

---

### Task 1 : `DESCRIPTION` côté serveur

**Files :**
- Modify : `lib/st_mesh_group_ops.py:931-946` (`CLIENT_MESSAGES`, constante de longueur, `METADATA_CLIENT_KEYS`)
- Modify : `lib/st_mesh_group_ops.py:1337-1378` (`_client_field_errors`, `_apply_client_form`)
- Create : `lab/tests/test_client_description.py`

**Interfaces :**
- Produces : clé `DESCRIPTION` (str) dans chaque ligne de `ops.list_clients(state)` quand elle existe ; erreur de champ `fields["DESCRIPTION"]` ; constante `CLIENT_DESCRIPTION_MAX = 500`.

- [ ] **Step 1 : écrire les tests qui échouent** dans `lab/tests/test_client_description.py`

Reprendre l'en-tête d'import, la fixture `state` et la fonction `form()` de `lab/tests/test_deployment_groups.py`
(sans `RELEASE`/`builtin_release`), avec un seul client
`{"UID": "SITE_A", "IP_ADDRESS": "10.0.0.4", "MESH_GROUP_UID_LIST": ["GROUP1"]}` et `dict_of_clients` à
`{"SITE_A": FakeClient("CONNECTED")}`. `disk = lambda s: toml.load(s["config_file_path"])["SERVER_CLIENT"][0]`.

```python
def test_description_is_saved_listed_and_does_not_reconnect(state):
    text = "Bureau de Québec\r\nRouteur Bell, contact : NOC 🛰️"
    preview = ops.update_client(state, "SITE_A", form(DESCRIPTION=text), actor="admin", dry_run=True)
    assert preview["affected_clients"] == []
    ops.update_client(state, "SITE_A", form(DESCRIPTION=text), actor="admin")
    assert disk(state)["DESCRIPTION"] == text
    assert ops.list_clients(state)[0]["DESCRIPTION"] == text

def test_description_is_stripped_and_500_chars_is_the_limit(state):
    ops.update_client(state, "SITE_A", form(DESCRIPTION="  " + "é" * 500 + "  "), actor="admin")
    assert disk(state)["DESCRIPTION"] == "é" * 500
    with pytest.raises(ops.OpError) as err:
        ops.update_client(state, "SITE_A", form(DESCRIPTION="x" * 501), actor="admin")
    assert err.value.status == 400 and "DESCRIPTION" in err.value.fields
    assert disk(state)["DESCRIPTION"] == "é" * 500

def test_empty_description_removes_the_key(state):
    ops.update_client(state, "SITE_A", form(DESCRIPTION="note"), actor="admin")
    ops.update_client(state, "SITE_A", form(DESCRIPTION="   "), actor="admin")
    assert "DESCRIPTION" not in disk(state)

def test_a_form_without_description_keeps_it(state):
    ops.update_client(state, "SITE_A", form(DESCRIPTION="note"), actor="admin")
    ops.update_client(state, "SITE_A", form(), actor="admin")
    assert disk(state)["DESCRIPTION"] == "note"

def test_a_new_client_can_have_a_description(state):
    ops.create_client(state, form(UID="SITE_B", IP_ADDRESS="10.0.0.5", DESCRIPTION="neuf"), actor="admin")
    assert toml.load(state["config_file_path"])["SERVER_CLIENT"][1]["DESCRIPTION"] == "neuf"
```

- [ ] **Step 2 : vérifier l'échec**

Run : `python -m pytest lab/tests/test_client_description.py -q`
Expected : FAIL (`DESCRIPTION` absente du disque / aucune erreur levée à 501).

- [ ] **Step 3 : implémenter dans `lib/st_mesh_group_ops.py`**

- `CLIENT_DESCRIPTION_MAX = 500` ; `CLIENT_MESSAGES["DESCRIPTION"] = "Up to 500 characters"`.
- `METADATA_CLIENT_KEYS = {"DEPLOYMENT_GROUP", "DESCRIPTION"}` ; mettre à jour le commentaire au-dessus (clés descriptives).
- `_client_field_errors` : `len(str(values.get("DESCRIPTION", "") or "").strip()) > CLIENT_DESCRIPTION_MAX` → `errors["DESCRIPTION"]`.
- `_apply_client_form` : bloc `if "DESCRIPTION" in values:` calqué sur celui de `DEPLOYMENT_GROUP` (strip, pose ou `pop`).

- [ ] **Step 4 : vérifier**

Run : `python -m pytest lab/tests/test_client_description.py lab/tests/test_deployment_groups.py lab/tests/test_mesh_group_ops.py -q`
Expected : tout PASS.

- [ ] **Step 5 : commit**

```bash
git add lib/st_mesh_group_ops.py lab/tests/test_client_description.py
git commit -m "feat(clients): description libre d'un client, sans reconnexion"
```

### Task 2 : champ et colonne dans la page Clients

**Files :**
- Modify : `lib/webui/templates/client_config.html:72-76` (zone de texte), `:196-199` (colonne), `:221` (`fill`), `:237` (`read`)
- Modify : `lib/webui/static/i18n/fr.json`

**Interfaces :**
- Consumes : `DESCRIPTION` dans `GET /api/v1/config/clients` et accepté par `POST`/`PUT` (Tâche 1) ; erreur de champ `DESCRIPTION`.

- [ ] **Step 1 : zone de texte** après la ligne `.row` des champs facultatifs (la macro `field` ne fait que des `<input>`) :
  `<div class="mb-3">` avec `<label for="c_desc">Description (optional)</label>`,
  `<textarea class="form-control" id="c_desc" data-field="DESCRIPTION" rows="3" maxlength="500" aria-describedby="c_desc_help">`,
  aide `id="c_desc_help"` : « Notes for administrators: location, network, contact. Has no effect on the measurements. »,
  puis `<div class="invalid-feedback" data-feedback="DESCRIPTION"></div>`.
- [ ] **Step 2 : `fill`** : `el("c_desc").value = row ? (row.DESCRIPTION || "") : "";` — **`read`** : `DESCRIPTION: el("c_desc").value.trim(),`.
- [ ] **Step 3 : colonne** après `DEPLOYMENT_GROUP` : `{field: "DESCRIPTION", title: "Description", formatter: ...}` qui renvoie `""` si vide, sinon
  `<span title="${st.esc(v)}">${st.esc(court)}</span>` où `court` = première ligne (`v.split(/\r?\n/)[0]`), coupée à 60 caractères + « … » si elle est plus longue ou s'il y a d'autres lignes.
- [ ] **Step 4 : traductions** dans `fr.json` (ordre alphabétique du fichier) :
  `"Description (optional)": "Description (facultatif)"` et
  `"Notes for administrators: location, network, contact. Has no effect on the measurements.": "Notes pour les administrateurs : emplacement, réseau, contact. Sans effet sur les mesures."`.
  (« Description » existe déjà.)
- [ ] **Step 5 : vérifier**

Run : `python -m pytest lab/tests/test_i18n.py lab/tests/test_webui_api.py -q`
Expected : tout PASS.

Manuel (lab, UI sur `http://127.0.0.1:18080`) : saisir `<b>"l'essai"</b>` + une seconde ligne → colonne montre le
texte littéral de la première ligne avec « … », infobulle complète ; rouvrir le client → texte intact ; 501
caractères collés via l'API → message d'erreur sous la zone.

- [ ] **Step 6 : commit**

```bash
git add lib/webui/templates/client_config.html lib/webui/static/i18n/fr.json
git commit -m "feat(webui): description d'un client dans la page Clients"
```
