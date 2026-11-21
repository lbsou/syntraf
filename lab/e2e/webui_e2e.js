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
    } catch (e) {
        await dump(page, "confirmation dialog expected");
        throw e;
    }
    const text = await page.$eval("#st-confirm-body", el => el.textContent);
    await page.click("#st-confirm-ok");
    await page.waitForSelector("#st-confirm", {hidden: true});
    return text;
}

// Prochain toast affiché après l'action (les précédents sont ignorés).
async function nextToast(page, action) {
    const before = await page.$$eval("#st-toasts .toast", els => els.length);
    await action();
    await page.waitForFunction(n => document.querySelectorAll("#st-toasts .toast").length > n, {timeout: 15000}, before);
    return page.$$eval("#st-toasts .toast", els => els.map(e => e.className + " | " + e.textContent.trim()).pop());
}

async function selectRow(page, uid) {
    // Comme un utilisateur : attendre qu'aucune fenêtre ni son fond assombri ne couvre la page.
    await page.waitForFunction(() => !document.querySelector(".modal-backdrop, .modal.show"), {timeout: 15000});
    await page.waitForFunction(u => [...document.querySelectorAll("#table tbody tr")].some(tr => tr.textContent.includes(u)), {}, uid);
    await page.evaluate(u => {
        $("#table").bootstrapTable("uncheckAll");
        $("#table").bootstrapTable("checkBy", {field: "UID", values: [u]});
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

    // 3. Tableau de bord en direct, journaux
    await page.goto(BASE + "/home.html", {waitUntil: "domcontentloaded"});
    await page.waitForSelector("#st-live.ok", {timeout: 15000});
    const clients = await page.$eval("#kpi-clients .st-kpi-value", el => el.textContent);
    check(/^\d+ \/ \d+$/.test(clients), `dashboard is live, clients connected: ${clients}`);
    await page.goto(BASE + "/log_viewer.html", {waitUntil: "domcontentloaded"});
    await page.waitForFunction(() => document.getElementById("meta").textContent.includes("line"), {timeout: 15000});
    check(true, "log viewer shows " + await page.$eval("#meta", el => el.textContent));

    await browser.close();
    console.log(failures.length ? `\n${failures.length} FAILURE(S)` : "\nALL CHECKS PASSED");
    process.exit(failures.length ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
