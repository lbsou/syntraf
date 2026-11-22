/* SYNTRAF webui : utilitaires partagés par toutes les pages (API, notifications, confirmation, diff, état en direct). */
(function (window, document) {
    "use strict";

    function esc(value) {
        return String(value === undefined || value === null ? "" : value)
            .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
    }

    // Appel de l'API REST. Renvoie {ok, status, data, error} ; error = {message, fields} en cas d'échec.
    async function api(method, url, body) {
        const opts = {method: method, headers: {"Accept": "application/json"}};
        if (body !== undefined) {
            opts.headers["Content-Type"] = "application/json";
            opts.body = JSON.stringify(body);
        }
        let response;
        try {
            response = await fetch(url, opts);
        } catch (e) {
            return {ok: false, status: 0, data: null, error: {message: "Server unreachable: " + e.message, fields: {}}};
        }
        const type = response.headers.get("Content-Type") || "";
        const data = type.includes("application/json") ? await response.json() : await response.text();
        if (response.ok) return {ok: true, status: response.status, data: data, error: null};
        const error = (data && data.error) ? data.error : {message: `HTTP ${response.status}`, fields: {}};
        return {ok: false, status: response.status, data: data, error: error};
    }

    function container() {
        let c = document.getElementById("st-toasts");
        if (!c) {
            c = document.createElement("div");
            c.id = "st-toasts";
            c.className = "toast-container position-fixed end-0 p-3 st-toasts";
            document.body.appendChild(c);
        }
        return c;
    }

    // Notification non bloquante. kind : success, danger, warning, info.
    function toast(message, kind) {
        kind = kind || "success";
        const el = document.createElement("div");
        el.className = `toast align-items-center text-bg-${kind} border-0`;
        el.setAttribute("role", kind === "danger" ? "alert" : "status");
        el.innerHTML = `<div class="d-flex"><div class="toast-body">${esc(message)}</div>` +
            `<button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button></div>`;
        container().appendChild(el);
        const t = new bootstrap.Toast(el, {delay: kind === "danger" ? 10000 : 4000});
        el.addEventListener("hidden.bs.toast", () => el.remove());
        t.show();
    }

    // Fermeture d'une fenêtre Bootstrap : ignorée par Bootstrap pendant son animation d'ouverture, elle est alors
    // reportée à la fin de l'ouverture.
    // Phase de capture : l'état est à jour avant les écouteurs posés sur la fenêtre elle-même (dont hideModal).
    document.addEventListener("show.bs.modal", e => { e.target.dataset.stShown = "0"; }, true);
    document.addEventListener("shown.bs.modal", e => { e.target.dataset.stShown = "1"; }, true);
    document.addEventListener("hide.bs.modal", e => { e.target.dataset.stShown = "0"; }, true);

    function hideModal(el) {
        const modal = bootstrap.Modal.getOrCreateInstance(el);
        if (el.dataset.stShown === "1") modal.hide();
        else el.addEventListener("shown.bs.modal", () => modal.hide(), {once: true});
    }

    // Boutons de fermeture natifs (data-bs-dismiss) cliqués pendant l'ouverture : fermeture différée, elle aussi.
    document.addEventListener("click", e => {
        const button = e.target.closest('[data-bs-dismiss="modal"]');
        const modalEl = button && button.closest(".modal");
        if (modalEl && modalEl.dataset.stShown !== "1") {
            e.preventDefault();
            e.stopImmediatePropagation();
            hideModal(modalEl);
        }
    }, true);

    // Fenêtre de confirmation. body : texte, ou nœud DOM. Renvoie une promesse booléenne.
    function confirm(opts) {
        return new Promise(resolve => {
            const modalEl = document.getElementById("st-confirm");
            document.getElementById("st-confirm-title").textContent = opts.title || "Confirm";
            const bodyEl = document.getElementById("st-confirm-body");
            bodyEl.innerHTML = "";
            if (opts.body instanceof Node) bodyEl.appendChild(opts.body);
            else bodyEl.textContent = opts.body || "";
            const ok = document.getElementById("st-confirm-ok");
            ok.textContent = opts.confirmText || "Confirm";
            ok.className = "btn " + (opts.danger ? "btn-danger" : "btn-primary");
            ok.disabled = !!opts.confirmDisabled;
            document.getElementById("st-confirm-cancel").hidden = !!opts.hideCancel;
            gate(bodyEl, ok);
            if (opts.confirmDisabled) ok.disabled = true;
            const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
            let answered = false;
            const onOk = () => { answered = true; hideModal(modalEl); };
            ok.addEventListener("click", onOk, {once: true});
            modalEl.addEventListener("hidden.bs.modal", () => {
                ok.removeEventListener("click", onOk);
                resolve(answered);
            }, {once: true});
            modal.show();
        });
    }

    // Diff unifié coloré, dans un <pre>.
    function diffNode(diff) {
        const pre = document.createElement("pre");
        pre.className = "st-diff";
        if (!diff) {
            pre.textContent = "No change to the configuration file.";
            return pre;
        }
        pre.innerHTML = diff.split("\n").map(line => {
            const cls = line.startsWith("@@") ? "hunk"
                : (line.startsWith("+") && !line.startsWith("+++")) ? "add"
                : (line.startsWith("-") && !line.startsWith("---")) ? "del" : "";
            return cls ? `<span class="${cls}">${esc(line)}</span>` : esc(line);
        }).join("\n");
        return pre;
    }

    // Aperçu d'un changement : diff du fichier et clients qui se reconnecteront.
    function previewNode(preview, intro) {
        const wrap = document.createElement("div");
        if (intro) {
            const p = document.createElement("p");
            p.textContent = intro;
            wrap.appendChild(p);
        }
        const clients = preview.affected_clients || [];
        const p = document.createElement("p");
        p.innerHTML = clients.length
            ? `<i class="fas fa-sync-alt me-1"></i>Clients whose measurements will restart: <strong>${clients.map(esc).join(", ")}</strong>`
            : `<i class="fas fa-check me-1"></i>No client measurement is affected.`;
        wrap.appendChild(p);
        const restart = preview.restart_required || [];
        if (restart.length) {
            const w = document.createElement("div");
            w.className = "alert alert-warning py-2";
            w.textContent = `Written to disk, but only applied after a server restart: ${restart.join(", ")}.`;
            wrap.appendChild(w);
        }
        if (preview.impact) wrap.appendChild(impactNode(preview.impact, preview.uid));
        wrap.appendChild(diffNode(preview.diff));
        return wrap;
    }

    // Impact d'un changement sur la capacité ; au-delà du seuil d'alerte, confirmation par saisie du nom.
    function impactNode(impact, name) {
        const box = document.createElement("div");
        const b = impact.busiest;
        const arrow = (x, y) => x === y ? esc(y) : `${esc(x)} → <strong>${esc(y)}</strong>`;
        box.innerHTML = `<table class="table table-sm small mb-2"><tbody>
            <tr><th scope="row">Measurement flows</th><td>${arrow(impact.flows_before, impact.flows_after)}${impact.added_flows ? ` (${impact.added_flows > 0 ? "+" : ""}${impact.added_flows})` : ""}
                <span class="text-white-50">· limit ${impact.limits.MAX_TOTAL_FLOWS}</span></td></tr>
            ${b ? `<tr><th scope="row">Busiest client</th><td>${esc(b.uid)}: ${b.processes} iperf3 processes, ${Math.round(b.kbps_out)} Kbps out
                <span class="text-white-50">· limit ${impact.limits.MAX_FLOWS_PER_CLIENT} flows per direction</span></td></tr>` : ""}
            <tr><th scope="row">Points written per second</th><td>${arrow(impact.points_per_s_before, impact.points_per_s_after)}</td></tr>
            </tbody></table>`;
        if (impact.alert) {
            const word = name || "CONFIRM";
            const alert = document.createElement("div");
            alert.className = "alert alert-danger py-2";
            alert.innerHTML = `<strong><i class="fas fa-exclamation-triangle me-1"></i>Large change:</strong> ${esc(impact.alert_reason)}.
                <label class="form-label small mt-2 mb-1 d-block" for="st-confirm-word">Type <code>${esc(word)}</code> to confirm</label>
                <input class="form-control form-control-sm" id="st-confirm-word" data-confirm-word="${esc(word)}" autocomplete="off">`;
            box.appendChild(alert);
        }
        return box;
    }

    // Bouton d'application bloqué tant que le mot de confirmation n'est pas saisi (s'il y en a un dans container).
    function gate(container, button) {
        const input = container.querySelector("[data-confirm-word]");
        if (!input) { button.disabled = false; return; }
        const sync = () => { button.disabled = input.value.trim() !== input.dataset.confirmWord; };
        input.addEventListener("input", sync);
        sync();
    }

    // URL d'application : ?confirm=1 quand l'aperçu demandait une confirmation (déjà saisie)
    function applyUrl(url, preview) {
        return preview && preview.impact && preview.impact.alert ? url + (url.includes("?") ? "&" : "?") + "confirm=1" : url;
    }

    // Erreurs par champ : marque les champs (data-field="NOM") invalides avec leur message.
    function showFieldErrors(form, fields) {
        form.querySelectorAll(".is-invalid").forEach(el => el.classList.remove("is-invalid"));
        Object.entries(fields || {}).forEach(([name, message]) => {
            const input = form.querySelector(`[data-field="${name}"]`);
            if (!input) return;
            input.classList.add("is-invalid");
            const fb = form.querySelector(`[data-feedback="${name}"]`);
            if (fb) fb.textContent = message;
        });
        const first = form.querySelector(".is-invalid");
        if (first) first.focus();
    }

    function setBusy(button, busy) {
        if (!button) return;
        if (busy) {
            button.dataset.label = button.innerHTML;
            button.disabled = true;
            button.innerHTML = `<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span>${esc(button.textContent.trim())}`;
        } else {
            button.disabled = false;
            if (button.dataset.label) button.innerHTML = button.dataset.label;
        }
    }

    // État en direct (Server-Sent Events) : un seul flux par page, partagé par les abonnés.
    const listeners = [];
    let source = null;

    function live(callback) {
        listeners.push(callback);
        if (source || !window.EventSource) return;
        const badge = () => document.getElementById("st-live");
        const set = (cls, text) => {
            const b = badge();
            if (!b) return;
            b.classList.remove("ok", "down");
            if (cls) b.classList.add(cls);
            b.querySelector(".st-live-text").textContent = text;
        };
        source = new EventSource("/api/v1/events");
        source.addEventListener("status", e => {
            const snap = JSON.parse(e.data);
            set("ok", "live · " + time(snap.time).slice(11));
            listeners.forEach(cb => cb(snap));
        });
        source.onerror = () => set("down", "reconnecting…");
        // Fermer le flux en quittant la page : sinon chaque page visitée garde une connexion ouverte et le navigateur
        // atteint sa limite de 6 connexions par serveur.
        window.addEventListener("pagehide", () => { if (source) { source.close(); source = null; } });
    }

    // Horodatage ISO (UTC) affiché en heure locale : AAAA-MM-JJ HH:MM:SS.
    function time(iso) {
        const d = new Date(iso);
        if (isNaN(d)) return iso || "";
        const p = n => String(n).padStart(2, "0");
        return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    }

    function badge(status) {
        return `<span class="badge st-status-${esc(status)}">${esc(status)}</span>`;
    }

    window.st = {esc, api, toast, confirm, diffNode, previewNode, showFieldErrors, setBusy, live, badge, time, hideModal,
                 gate, applyUrl};

    // Indicateur « live » sur toutes les pages, même sans abonné.
    document.addEventListener("DOMContentLoaded", () => live(() => {}));
})(window, document);
