/* Langue de l'interface : anglais (textes d'origine) ou français.
 *
 * Les textes restent écrits en anglais dans les gabarits et le JavaScript ; en français, chaque nœud de texte et les
 * attributs title, placeholder et aria-label dont le contenu est une clé de static/i18n/fr.json sont remplacés, y
 * compris ceux ajoutés plus tard (tableaux, toasts, fenêtres de confirmation, erreurs de l'API) grâce à un
 * MutationObserver. Une clé peut contenir {0}, {1}… : valeurs variables (nom d'un client, nombre…), elles-mêmes
 * traduites si ce sont des clés. Choix mémorisé (localStorage) ; par défaut, la langue du navigateur.
 * Textes à traduire : python -m lib.web_ui_kindafixed2.i18n_extract
 */
(function () {
    "use strict";
    const KEY = "st_lang";
    const LANGS = ["en", "fr"];
    const ATTRS = ["title", "placeholder", "aria-label"];
    const SKIP = new Set(["SCRIPT", "STYLE", "CODE", "PRE", "TEXTAREA", "KBD", "SAMP"]);
    const DICT_URL = (document.currentScript && document.currentScript.dataset.dict) || "/static/i18n/";

    function chosen() {
        let lang = null;
        try { lang = localStorage.getItem(KEY); } catch (e) { /* stockage bloqué */ }
        if (!LANGS.includes(lang)) lang = (navigator.language || "en").toLowerCase().startsWith("fr") ? "fr" : "en";
        return lang;
    }

    const lang = chosen();
    document.documentElement.lang = lang;
    const st = window.st_i18n = {lang, LANGS, t: s => s, set: setLang};

    function setLang(value) {
        if (!LANGS.includes(value) || value === lang) return;
        try { localStorage.setItem(KEY, value); } catch (e) { /* stockage bloqué */ }
        document.cookie = `${KEY}=${value}; path=/; max-age=31536000; samesite=lax`;
        location.reload();
    }

    if (lang === "en") return;

    // Masque la page jusqu'à la première traduction : pas d'anglais furtif
    document.documentElement.classList.add("st-i18n-pending");

    const exact = new Map();
    const patterns = [];

    function load(dict) {
        for (const [en, tr] of Object.entries(dict)) {
            if (/\{\d+\}/.test(en)) {
                const names = [];
                const source = en.split(/(\{\d+\})/).map(part => {
                    const m = part.match(/^\{(\d+)\}$/);
                    if (m) { names.push(+m[1]); return "(.+?)"; }
                    return part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
                }).join("");
                patterns.push({re: new RegExp(`^${source}$`, "s"), names, tr, weight: en.replace(/\{\d+\}/g, "").length});
            } else {
                exact.set(en, tr);
            }
        }
        patterns.sort((a, b) => b.weight - a.weight);  // le modèle le plus précis d'abord
    }

    function translate(text, depth = 0) {
        const core = text.replace(/\s+/g, " ").trim();  // un texte de gabarit peut s'étendre sur plusieurs lignes
        if (!core) return text;
        let out = exact.get(core);
        if (out === undefined) {
            for (const p of patterns) {
                const m = core.match(p.re);
                if (!m) continue;
                const values = {};
                // une valeur peut elle-même être un texte à traduire (« · Mesh group 'X' deleted »)
                p.names.forEach((n, i) => { values[n] = depth < 2 ? translate(m[i + 1], depth + 1) : m[i + 1]; });
                out = p.tr.replace(/\{(\d+)\}/g, (_, n) => (n in values ? values[n] : ""));
                break;
            }
        }
        if (out === undefined || out === core) return text;
        const lead = text.match(/^\s*/)[0], trail = text.match(/\s*$/)[0];
        return lead + out + trail;
    }
    st.t = translate;

    function skipped(el) {
        for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
            if (SKIP.has(n.tagName) || n.hasAttribute("data-no-i18n") || n.isContentEditable) return true;
        }
        return false;
    }

    function translateNode(node) {
        if (node.nodeType === 3) {
            if (node.parentElement && !skipped(node.parentElement)) {
                const tr = translate(node.nodeValue);
                if (tr !== node.nodeValue) node.nodeValue = tr;
            }
            return;
        }
        if (node.nodeType !== 1 || skipped(node)) return;
        for (const a of ATTRS) {
            const v = node.getAttribute(a);
            if (v) { const tr = translate(v); if (tr !== v) node.setAttribute(a, tr); }
        }
        if (node.tagName === "INPUT" && (node.type === "button" || node.type === "submit") && node.value) {
            const tr = translate(node.value); if (tr !== node.value) node.value = tr;
        }
        const walker = document.createTreeWalker(node, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
        for (let n = walker.nextNode(); n; n = walker.nextNode()) {
            if (n.nodeType === 3) {
                if (!skipped(n.parentElement)) { const tr = translate(n.nodeValue); if (tr !== n.nodeValue) n.nodeValue = tr; }
            } else if (!skipped(n)) {
                for (const a of ATTRS) {
                    const v = n.getAttribute(a);
                    if (v) { const tr = translate(v); if (tr !== v) n.setAttribute(a, tr); }
                }
            }
        }
    }

    function translateTitle() {
        const parts = document.title.split(" · ");
        const tr = parts.map(p => translate(p)).join(" · ");
        if (tr !== document.title) document.title = tr;
    }

    function start() {
        translateNode(document.body);
        translateTitle();
        document.documentElement.classList.remove("st-i18n-pending");
        new MutationObserver(records => {
            for (const r of records) {
                if (r.type === "characterData") translateNode(r.target);
                else if (r.type === "attributes") translateNode(r.target);
                else r.addedNodes.forEach(translateNode);
            }
        }).observe(document.body, {childList: true, subtree: true, characterData: true,
                                   attributes: true, attributeFilter: ATTRS});
    }

    // Dictionnaire chargé de façon synchrone : la page est traduite avant son premier affichage
    try {
        const xhr = new XMLHttpRequest();
        xhr.open("GET", `${DICT_URL}${lang}.json`, false);
        xhr.send();
        if (xhr.status === 200) load(JSON.parse(xhr.responseText));
    } catch (e) { /* sans dictionnaire : anglais */ }

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
    else start();
    // Filet de sécurité : jamais de page masquée
    setTimeout(() => document.documentElement.classList.remove("st-i18n-pending"), 1500);
})();
