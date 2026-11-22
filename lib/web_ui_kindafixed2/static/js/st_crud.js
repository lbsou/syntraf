/* SYNTRAF webui : page de configuration éditable (tableau + création / modification / suppression).
 *
 * Gabarit attendu : #table, #btn_new, #btn_edit, #btn_delete, et la fenêtre #modal_form contenant
 * #cfg_form > #cfg_fields (champs, data-field="NOM") et #cfg_review, #modal_form_title, #btn_save, #btn_back, #btn_apply.
 *
 * Chaque changement passe par un aperçu (?dry_run=1 : diff et clients touchés) avant d'être appliqué.
 */
(function (window) {
    "use strict";

    window.st.crud = function (opts) {
        const $table = $("#table");
        const form = document.getElementById("cfg_form");
        const modalEl = document.getElementById("modal_form");
        const modal = new bootstrap.Modal(modalEl);
        const el = id => document.getElementById(id);
        let editing = null, pending = null, rows = [];

        const selection = () => $table.bootstrapTable("getSelections");

        function refreshButtons() {
            const n = selection().length;
            el("btn_edit").disabled = n !== 1;
            el("btn_delete").disabled = n === 0;
        }

        async function load() {
            document.body.dataset.tableLoaded = "0";  // repère pour les tests de bout en bout : tableau en cours de chargement
            const r = await st.api("GET", opts.listUrl);
            if (!r.ok) { st.toast(r.error.message, "danger"); return; }
            rows = r.data;
            $table.bootstrapTable("destroy").bootstrapTable({
                data: rows, uniqueId: opts.idField, clickToSelect: true, search: true, pagination: true,
                formatNoMatches: () => opts.emptyText, columns: [{field: "state", checkbox: true}].concat(opts.columns),
            });
            refreshButtons();
            document.body.dataset.tableLoaded = "1";
            if (opts.onLoad) opts.onLoad(rows);
        }
        $table.on("check.bs.table uncheck.bs.table check-all.bs.table uncheck-all.bs.table " +
                  "check-some.bs.table uncheck-some.bs.table post-body.bs.table", refreshButtons);

        function stage(review) {
            el("cfg_fields").hidden = review;
            el("cfg_review").hidden = !review;
            el("btn_save").hidden = review;
            el("btn_back").hidden = !review;
            el("btn_apply").hidden = !review;
        }

        async function open(row) {
            editing = row ? row[opts.idField] : null;
            form.reset();
            stage(false);
            st.showFieldErrors(form, {});
            el("modal_form_title").textContent = row ? opts.titleEdit(editing) : opts.titleNew;
            await opts.fill(row);
            modal.show();
        }

        function report(result) {
            if (!result.ok) { st.toast(result.error.message, "danger"); return false; }
            const d = result.data, parts = [d.message + "."];
            if ((d.reconnected_clients || []).length) parts.push(`${d.reconnected_clients.length} client(s) reconnecting.`);
            if ((d.recreated_databases || []).length) parts.push(`Connection re-created: ${d.recreated_databases.join(", ")}.`);
            const restart = d.restart_required || [];
            if (restart.length) parts.push(`Restart the server to apply: ${restart.join(", ")}.`);
            st.toast(parts.join(" "), restart.length ? "warning" : "success");
            return true;
        }

        form.addEventListener("submit", async e => {
            e.preventDefault();
            const body = opts.read();
            const method = editing ? "PUT" : "POST";
            const url = editing ? opts.itemUrl(editing) : opts.listUrl;
            st.setBusy(el("btn_save"), true);
            const preview = await st.api(method, url + "?dry_run=1", body);
            st.setBusy(el("btn_save"), false);
            if (!preview.ok) {
                st.showFieldErrors(form, preview.error.fields);
                if (!Object.keys(preview.error.fields || {}).length) st.toast(preview.error.message, "danger");
                return;
            }
            st.showFieldErrors(form, {});
            pending = {method, url, body};
            const node = st.previewNode(preview.data, editing ? `Changes to “${editing}”:` : `New: “${body[opts.idField]}”`);
            const dbs = preview.data.recreated_databases || [];
            if (dbs.length) {
                const p = document.createElement("p");
                p.innerHTML = `<i class="fas fa-database me-1"></i>Database connection re-created: <strong>${dbs.map(st.esc).join(", ")}</strong>`;
                node.insertBefore(p, node.querySelector(".st-diff"));
            }
            el("cfg_review").replaceChildren(node);
            stage(true);
            el("btn_apply").focus();
        });

        el("btn_back").addEventListener("click", () => stage(false));
        el("btn_apply").addEventListener("click", async () => {
            st.setBusy(el("btn_apply"), true);
            const r = await st.api(pending.method, pending.url, pending.body);
            st.setBusy(el("btn_apply"), false);
            if (!r.ok) { stage(false); st.showFieldErrors(form, r.error.fields); st.toast(r.error.message, "danger"); return; }
            st.hideModal(modalEl);
            report(r);
            load();
        });

        el("btn_new").addEventListener("click", () => open(null));
        el("btn_edit").addEventListener("click", () => open(selection()[0]));
        el("btn_delete").addEventListener("click", async () => {
            const ids = selection().map(r => r[opts.idField]);
            if (ids.length === 1) {
                const preview = await st.api("DELETE", opts.itemUrl(ids[0]) + "?dry_run=1");
                if (!preview.ok) { st.toast(preview.error.message, "danger"); return; }
                const ok = await st.confirm({title: opts.deleteTitle(ids[0]), body: st.previewNode(preview.data, opts.deleteWarning),
                                             confirmText: "Delete", danger: true});
                if (ok && report(await st.api("DELETE", opts.itemUrl(ids[0])))) load();
                return;
            }
            const ok = await st.confirm({title: `Delete ${ids.length} items?`, body: ids.join(", ") + ". " + opts.deleteWarning,
                                         confirmText: "Delete", danger: true});
            if (!ok) return;
            for (const id of ids) report(await st.api("DELETE", opts.itemUrl(id)));
            load();
        });

        load();
        return {load, rows: () => rows, editing: () => editing};
    };
})(window);
