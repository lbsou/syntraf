// Test de bout en bout de la webui dans un vrai navigateur (Chrome via puppeteer-core).
//
//   cd lab/e2e && npm install && node webui_e2e.js
//   Variables : SYNTRAF_URL (défaut http://127.0.0.1:18080), CHROME_PATH (chemin de Chrome / Chromium).
//
// 1. Chaque page du menu : HTTP 200, aucune erreur JavaScript, aucune ressource en échec.
// 2. Mesh group temporaire (sans membre, donc sans effet sur les mesures) : erreur de champ, création avec aperçu,
//    désactivation, suppression ; puis sa trace dans « Audit & versions ».
// 3. Tableau de bord alimenté en direct, journaux affichés.
"use strict";
const puppeteer = require(process.env.PUPPETEER_CORE || "puppeteer-core");

const BASE = process.env.SYNTRAF_URL || "http://127.0.0.1:18080";
const CHROME = process.env.CHROME_PATH || {
    win32: "C:/Program Files/Google/Chrome/Application/chrome.exe",
    darwin: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
}[process.platform] || "/usr/bin/chromium";
const GROUP = "E2E_TMPGRP";

const failures = [];
const check = (ok, what) => { console.log(`${ok ? "OK  " : "FAIL"} ${what}`); if (!ok) failures.push(what); };

async function dump(page, why) {
    const state = await page.evaluate(() => JSON.stringify({
        modals: [...document.querySelectorAll(".modal")].map(m => m.id + ":" + m.className),
        toasts: [...document.querySelectorAll("#st-toasts .toast")].map(t => t.textContent.trim()),
        invalid: [...document.querySelectorAll(".is-invalid")].map(e => e.id)}));
    await page.screenshot({path: "e2e_failure.png"});
    console.log(`DUMP (${why}): ${state} — screenshot: e2e_failure.png`);
}

async function confirmModal(page) {
    try {
        await page.waitForSelector("#st-confirm.show #st-confirm-ok", {visible: true, timeout: 15000});
        // comme un utilisateur : cliquer une fois la fenêtre en place (pendant l'animation, le bouton se déplace)
        await page.waitForSelector('#st-confirm[data-st-shown="1"]', {timeout: 15000});
    } catch (e) {
        await dump(page, "confirmation dialog expected");
        throw e;
    }
    const text = await page.$eval("#st-confirm-body", el => el.textContent);
    await page.click("#st-confirm-ok");
    try {
        await page.waitForSelector("#st-confirm", {hidden: true, timeout: 15000});
    } catch (e) {
        const hit = await page.evaluate(() => {
            const r = document.getElementById("st-confirm-ok").getBoundingClientRect();
            const e = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
            return `${e.tagName}#${e.id}.${e.className}`;
        });
        console.log("element under the OK button:", hit);
        await dump(page, "confirmation dialog should have closed");
        throw e;
    }
    return text;
}

// Prochain toast affiché après l'action (les précédents sont ignorés).
async function nextToast(page, action) {
    const before = await page.$$eval("#st-toasts .toast", els => els.length);
    await action();
    await page.waitForFunction(n => document.querySelectorAll("#st-toasts .toast").length > n, {timeout: 15000}, before);
    return page.$$eval("#st-toasts .toast", els => els.map(e => e.className + " | " + e.textContent.trim()).pop());
}

// Pages éditables (st_crud.js) : formulaire, aperçu, application. Renvoie le texte de l'aperçu.
async function reviewAndApply(page) {
    await page.click("#btn_save");
    await page.waitForSelector("#btn_apply", {visible: true});
    const preview = await page.$eval("#cfg_review", e => e.textContent);
    await nextToast(page, () => page.click("#btn_apply"));
    await page.waitForFunction(() => !document.querySelector(".modal-backdrop, .modal.show"), {timeout: 15000});
    // le tableau est rechargé (reconstruit) après l'application : attendre, sinon une sélection serait perdue
    await page.waitForSelector('body[data-table-loaded="1"]', {timeout: 15000});
    return preview;
}

async function crudCreate(page, fill) {
    await page.click("#btn_new");
    await page.waitForSelector("#modal_form.show", {visible: true});
    await fill();
    return reviewAndApply(page);
}

async function rowExists(page, field, uid) {
    await page.waitForFunction(u => $("#table").bootstrapTable("getRowByUniqueId", u) !== null, {timeout: 15000}, uid);
    return true;
}

async function selectRow(page, uid) {
    // Comme un utilisateur : attendre qu'aucune fenêtre ni son fond assombri ne couvre la page.
    await page.waitForFunction(() => !document.querySelector(".modal-backdrop, .modal.show"), {timeout: 15000});
    await page.waitForFunction(u => [...document.querySelectorAll("#table tbody tr")].some(tr => tr.textContent.includes(u)), {}, uid);
    await page.evaluate(u => {
        $("#table").bootstrapTable("uncheckAll");
        const field = $("#table").bootstrapTable("getOptions").uniqueId || "UID";  // UID ou DB_UID
        $("#table").bootstrapTable("checkBy", {field: field, values: [u]});
    }, uid);
}

(async () => {
    const browser = await puppeteer.launch({executablePath: CHROME, headless: "new", args: ["--no-sandbox"]});
    const page = await browser.newPage();
    await page.setViewport({width: 1400, height: 900});
    let errors = [];
    page.on("pageerror", e => errors.push("JS: " + e.message));
    page.on("console", m => { if (m.type() === "error") errors.push("console: " + m.text()); });
    page.on("requestfailed", r => { if (!r.url().includes("/api/v1/events")) errors.push("failed: " + r.url()); });
    page.on("response", r => { if (r.status() >= 400) errors.push(`HTTP ${r.status()} ${r.url()}`); });

    // 1. Toutes les pages du menu
    await page.goto(BASE + "/", {waitUntil: "domcontentloaded"});
    const links = await page.$$eval("#st-sidebar a.nav-link", as => as.map(a => a.getAttribute("href")));
    check(links.length >= 10, `menu has ${links.length} entries`);
    for (const href of links) {
        errors = [];
        const r = await page.goto(BASE + href, {waitUntil: "domcontentloaded"});
        await new Promise(res => setTimeout(res, 1500));
        check(r.status() === 200 && errors.length === 0, `page ${href} (HTTP ${r.status()}) ${errors.join(" ; ")}`);
    }

    // 2. Cycle de vie d'un mesh group temporaire
    errors = [];
    await page.goto(BASE + "/mesh_group_config.html", {waitUntil: "domcontentloaded"});
    await page.waitForSelector("#table tbody tr");
    const exists = await page.evaluate(g => $("#table").bootstrapTable("getRowByUniqueId", g) !== null, GROUP);
    if (exists) {  // reste d'une exécution interrompue
        await selectRow(page, GROUP);
        await page.click("#btn_delete");
        await nextToast(page, () => confirmModal(page));
    }

    await page.click("#btn_new");
    await page.waitForSelector("#modal_form.show #mg_name", {visible: true});
    // Topologie : cartes cliquables ; les hubs n'apparaissent qu'en hub & spoke (un) et deux hubs (deux)
    await page.click('label[for="topo_dual"]');
    const dual = await page.$eval("#mg_hubs", e => !e.hidden) && await page.$eval("#mg_hub2_wrap", e => !e.hidden);
    await page.click('label[for="topo_hub"]');
    const single = await page.$eval("#mg_hub2_wrap", e => e.hidden);
    await page.click('label[for="topo_mesh"]');
    const mesh = await page.$eval("#mg_hubs", e => e.hidden);
    check(dual && single && mesh, "topology cards show the right hub choices (dual: 2, hub & spoke: 1, mesh: none)");
    await page.type("#mg_name", GROUP);
    await page.type("#mg_packet_size", "100");
    await page.click("#btn_save");
    await page.waitForSelector('#mg_bandwidth.is-invalid', {visible: true});
    const feedback = await page.$eval('[data-feedback="BANDWIDTH"]', el => el.textContent);
    check(feedback.length > 0, `empty bandwidth is flagged on the field: “${feedback}”`);

    await page.type("#mg_bandwidth", "10");
    await page.click("#btn_save");
    await page.waitForSelector("#btn_apply", {visible: true});
    const preview = await page.$eval("#mg_review", el => el.textContent);
    let toast = await nextToast(page, () => page.click("#btn_apply"));
    check(preview.includes("No client measurement is affected") && preview.includes(`UID = "${GROUP}"`),
          "creation preview shows the diff and no affected client");
    check(toast.includes("text-bg-success") && toast.includes(`'${GROUP}' created`), `creation toast: ${toast}`);

    await selectRow(page, GROUP);
    const label = await page.$eval("#btn_disable_text", el => el.textContent);
    check(label === "Disable", `toggle button reads “${label}”`);
    await page.click("#btn_disable");
    const disablePreview = await confirmModal(page);
    check(disablePreview.includes("DISABLED = true"), "disable preview shows DISABLED = true");
    await page.waitForFunction(g => {
        const row = $("#table").bootstrapTable("getRowByUniqueId", g);
        return row && row.DISABLED === true;
    }, {timeout: 15000}, GROUP);
    check(true, "group shown as disabled");

    await selectRow(page, GROUP);
    await page.click("#btn_delete");
    await confirmModal(page);
    await page.waitForFunction(g => $("#table").bootstrapTable("getRowByUniqueId", g) === null, {timeout: 15000}, GROUP);
    check(true, "group deleted");
    check(errors.filter(e => !e.includes("HTTP 400") && !e.includes("status of 400")).length === 0, `no error during the mesh group cycle ${errors.join(" ; ")}`);

    // Trace dans l'audit
    await page.goto(BASE + "/audit.html", {waitUntil: "domcontentloaded"});
    await page.waitForSelector("#audit-list .accordion-item");
    const audit = await page.$eval("#audit-list", el => el.textContent);
    check(["CREATE_MESH_GROUP", "DISABLE_MESH_GROUP", "DELETE_MESH_GROUP"].every(a => audit.includes(a)) && audit.includes(GROUP),
          "audit lists the creation, the disabling and the deletion");
    await page.click("#tab-versions");
    await page.waitForSelector("#versions-body button[data-act=restore]");
    check(true, "versions tab lists restorable versions");

    // Profil temporaire (inutilisé, donc sans effet sur les mesures) : création, modification, suppression.
    const PROFILE = "E2E_PROFILE";
    // reste d'une exécution interrompue
    await page.evaluate(p => fetch(`/api/v1/config/profiles/${p}`, {method: "DELETE"}), PROFILE);
    errors = [];
    await page.goto(BASE + "/profile_config.html", {waitUntil: "domcontentloaded"});
    await page.waitForSelector('body[data-table-loaded="1"]');
    await page.waitForSelector("#table");
    await crudCreate(page, async () => {
        await page.type("#p_uid", PROFILE);
        await page.type("#p_dscp", "46");
    });
    check(await rowExists(page, "UID", PROFILE), "profile created");
    await selectRow(page, PROFILE);
    await page.click("#btn_edit");
    await page.waitForSelector("#modal_form.show #p_dscp", {visible: true});
    await page.$eval("#p_dscp", e => { e.value = ""; });
    await page.type("#p_dscp", "34");
    const profilePreview = await reviewAndApply(page);
    check(profilePreview.includes('DSCP = "34"') && profilePreview.includes("No client measurement is affected"),
          "profile edit preview shows the new DSCP and no affected client");
    await selectRow(page, PROFILE);
    await page.click("#btn_delete");
    await nextToast(page, () => confirmModal(page));
    await page.waitForFunction(u => $("#table").bootstrapTable("getRowByUniqueId", u) === null, {timeout: 15000}, PROFILE);
    check(errors.length === 0, `profile cycle without error ${errors.join(" ; ")}`);

    // Client : aperçu d'une modification (MAX_BANDWIDTH), puis abandon sans appliquer.
    await page.goto(BASE + "/client_config.html", {waitUntil: "domcontentloaded"});
    await page.waitForSelector('body[data-table-loaded="1"]');
    await page.waitForSelector("#table tbody tr");
    const firstClient = await page.evaluate(() => $("#table").bootstrapTable("getData")[0].UID);
    await selectRow(page, firstClient);
    await page.click("#btn_edit");
    await page.waitForSelector("#modal_form.show #c_max_bw", {visible: true});
    await page.type("#c_max_bw", "50M");
    await page.click("#btn_save");
    await page.waitForSelector("#btn_apply", {visible: true});
    const clientPreview = await page.$eval("#cfg_review", e => e.textContent);
    check(clientPreview.includes('MAX_BANDWIDTH = "50M"'), `client edit preview shows MAX_BANDWIDTH for ${firstClient}`);
    await page.click("#modal_form [data-bs-dismiss=modal]");
    await page.waitForFunction(() => !document.querySelector(".modal.show"), {timeout: 15000});

    // Base de données : test de connexion sans enregistrer.
    await page.goto(BASE + "/database_config.html", {waitUntil: "domcontentloaded"});
    await page.waitForSelector('body[data-table-loaded="1"]');
    await page.waitForSelector("#table tbody tr");
    const firstDb = await page.evaluate(() => $("#table").bootstrapTable("getData")[0].DB_UID);
    await selectRow(page, firstDb);
    await page.click("#btn_edit");
    try {
        await page.waitForSelector("#modal_form.show #btn_test", {visible: true, timeout: 15000});
    } catch (e) {
        console.log("errors so far:", errors.join(" ; "));
        await dump(page, "database edit form expected");
        throw e;
    }
    await page.click("#btn_test");
    await page.waitForFunction(() => document.getElementById("test_result").textContent.trim().length > 0, {timeout: 20000});
    const tested = await page.$eval("#test_result", e => e.textContent.trim());
    check(tested.includes("ONLINE"), `database ${firstDb} connection test: ${tested}`);
    await page.click("#modal_form [data-bs-dismiss=modal]");

    // 3. Tableau de bord en direct, journaux
    await page.goto(BASE + "/home.html", {waitUntil: "domcontentloaded"});
    await page.waitForSelector("#st-live.ok", {timeout: 15000});
    const clients = await page.$eval("#kpi-clients .st-kpi-value", el => el.textContent);
    check(/^\d+ \/ \d+$/.test(clients), `dashboard is live, clients connected: ${clients}`);
    await page.goto(BASE + "/log_viewer.html", {waitUntil: "domcontentloaded"});
    await page.waitForFunction(() => document.getElementById("meta").textContent.includes("entr"), {timeout: 15000});
    const nodes = await page.$$eval("#f_nodes input", els => els.map(e => e.value));
    check(nodes.includes("server") && nodes.length >= 2, `log viewer lists the server and the clients: ${nodes.join(", ")}`);
    await page.select("#f_level", "");
    await page.select("#f_since", "1d");
    await page.waitForFunction(() => document.querySelectorAll("#rows tr[data-i]").length > 0, {timeout: 15000});
    const clientRows = await page.$$eval("#rows tr[data-i] .badge.bg-secondary", els => els.length);
    check(clientRows > 0, "log viewer shows " + await page.$eval("#meta", el => el.textContent) + `, ${clientRows} from clients`);

    await browser.close();
    console.log(failures.length ? `\n${failures.length} FAILURE(S)` : "\nALL CHECKS PASSED");
    process.exit(failures.length ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
