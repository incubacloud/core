/** @odoo-module **/

import { Component, useState, useEnv } from "@odoo/owl";
import { rpc } from "@web/core/network/rpc";
import { _t } from "@web/core/l10n/translation";
import { parseUTC } from "../../utils/dates";
import { IcModal } from "../ic_modal/ic_modal";
import { IcPager } from "../ic_pager/ic_pager";

export class AlertHistory extends Component {
    static template = "incubacloud.AlertHistory";
    static components = { IcModal, IcPager };
    static props = {
        embedded: { type: Boolean, optional: true },
    };

    setup() {
        this.env = useEnv();
        this.state = useState({
            alerts: [],
            total: 0,
            offset: 0,
            loading: true,
            stateFilter: "active",
            levelFilter: "all",      // all | warning | critical
            resolveModal: null,      // { alert, choices: { [pkgName]: chosen_spec } }
            addonConflictModal: null, // { alert }
            dismissAllModal: false,  // bulk-dismiss confirmation
            expanded: {},            // { [alertId]: bool } — controls payload reveal
        });
        this.loadAlerts();
    }

    /** Server-side page size for the alert list. */
    get pageSize() {
        return 20;
    }

    /**
     * Toggle the "show details" disclosure for an alert whose payload
     * carries structured detail (e.g. deduped error log groups).
     * @param {number} alertId
     */
    toggleExpanded(alertId) {
        this.state.expanded[alertId] = !this.state.expanded[alertId];
    }

    goBack() {
        const returnUrl = this.env.getAlertReturnUrl?.();
        if (returnUrl) {
            history.pushState(null, "", returnUrl);
            window.dispatchEvent(new PopStateEvent("popstate"));
        } else {
            this.env.navigate("projects");
        }
    }

    async loadAlerts() {
        this.state.loading = true;
        const data = await rpc("/cloud/get_alert_history", {
            state_filter: this.state.stateFilter,
            level_filter: this.state.levelFilter,
            offset: this.state.offset,
            limit: this.pageSize,
        });
        this.state.alerts = data.alerts;
        this.state.total = data.total;
        this.state.loading = false;
        this.env.refreshAlertCount();
    }

    setFilter(f) {
        this.state.stateFilter = f;
        this.state.offset = 0;
        this.loadAlerts();
    }

    setLevelFilter(f) {
        this.state.levelFilter = f;
        this.state.offset = 0;
        this.loadAlerts();
    }

    /**
     * IcPager callback — jump to the page starting at *offset*.
     * @param {number} offset new zero-based row offset
     */
    goPage(offset) {
        this.state.offset = offset;
        this.loadAlerts();
    }

    /**
     * Whether the bulk "Dismiss all" affordance makes sense for the
     * current view: something is listed and we are not looking at
     * already-dismissed history.
     */
    get canDismissAll() {
        return this.state.stateFilter !== "dismissed" && this.state.total > 0;
    }

    openDismissAll() {
        this.state.dismissAllModal = true;
    }

    closeDismissAll() {
        this.state.dismissAllModal = false;
    }

    /**
     * Bulk-dismiss the active non-conflict alerts (server enforces the
     * conflict exclusion and record-rule scoping), then reload.
     */
    async confirmDismissAll() {
        this.state.dismissAllModal = false;
        try {
            const res = await rpc("/cloud/dismiss_all_alerts", {
                level_filter: this.state.levelFilter,
            });
            this.env.toast?.success(
                _t("%s alert(s) dismissed", res.count),
            );
        } catch (_e) {
            this.env.toast?.error(_t("Failed to dismiss alerts"));
        }
        this.state.offset = 0;
        await this.loadAlerts();
    }

    openJob(jobId) {
        window.open(`/cloud/log/${jobId}`, "_blank");
    }

    goToInstance(alert) {
        if (alert.instance_id && alert.project_id) {
            this.env.navigate("instance_detail", {
                project_id: alert.project_id,
                instance_id: alert.instance_id,
            });
        }
    }

    openResolve(alert) {
        // Pre-fill choices: default to "existing" for all conflicts
        const choices = {};
        for (const c of (alert.conflict_data || [])) {
            choices[c.name] = c.existing;
        }
        this.state.resolveModal = { alert, choices };
    }

    setChoice(pkgName, spec) {
        if (this.state.resolveModal) {
            this.state.resolveModal.choices[pkgName] = spec;
        }
    }

    resolveManually() {
        const { alert } = this.state.resolveModal;
        this.state.resolveModal = null;
        // Do NOT dismiss — the alert stays active until the field is clean.
        // enqueue() will auto-dismiss it when no conflicts remain.
        if (alert.instance_id) {
            this.env.navigate("instance_detail", {
                instance_id: alert.instance_id,
                project_id: alert.project_id,
            });
        }
    }

    async confirmResolve() {
        const { alert, choices } = this.state.resolveModal;
        this.state.resolveModal = null;
        await rpc("/cloud/resolve_pip_conflict", {
            alert_id: alert.id,
            resolutions: choices,
        });
        await this.loadAlerts();
    }

    closeResolveModal() {
        this.state.resolveModal = null;
    }

    openAddonConflict(alert) {
        // Pre-select the first repo for each conflict
        const choices = {};
        for (const c of (alert.conflict_data || [])) {
            choices[c.addon] = (c.repos || [])[0] || '';
        }
        this.state.addonConflictModal = { alert, choices };
    }

    closeAddonConflictModal() {
        this.state.addonConflictModal = null;
    }

    setAddonChoice(addon, repo) {
        if (this.state.addonConflictModal) {
            this.state.addonConflictModal.choices[addon] = repo;
        }
    }

    async confirmResolveAddon() {
        const { alert, choices } = this.state.addonConflictModal;
        this.state.addonConflictModal = null;
        await rpc("/cloud/resolve_addon_conflict", {
            alert_id: alert.id,
            resolutions: choices,
        });
        await this.loadAlerts();
    }

    async dismissAlert(alert) {
        await rpc("/cloud/dismiss_alert", { alert_id: alert.id });
        await this.loadAlerts();
    }

    /**
     * Formatted "last seen" stamp for an alert, or "" when it would
     * only repeat what the creation date already says.
     *
     * An alert that keeps being re-raised (a cron failing every six
     * hours) shows the same creation date for days, which reads as
     * stale. The stamp is what says the problem is still happening.
     *
     * @param {Object} alert alert entry from ``get_alert_history``
     * @returns {string} formatted stamp, or "" when there is nothing
     *   worth showing
     */
    lastSeen(alert) {
        if (!alert.last_raised_at) return "";
        const seen = this.formatDate(alert.last_raised_at);
        return seen === this.formatDate(alert.create_date) ? "" : seen;
    }

    formatDate(dateStr) {
        if (!dateStr) return "—";
        const d = parseUTC(dateStr);
        return d.toLocaleString([], {
            month: "2-digit", day: "2-digit",
            hour: "2-digit", minute: "2-digit",
        });
    }

    /**
     * View-only mapping of an alert ``level`` to the Relay severity-banner
     * modifier class (``rl-sevban`` variant): ``info`` / ``warning`` /
     * ``critical``. Anything not warning/critical falls back to ``info``.
     * No business logic — only selects the banner colour.
     * @param {string} level raw alert level
     * @returns {string} one of "info" | "warning" | "critical"
     */
    levelClass(level) {
        if (level === "critical") return "critical";
        if (level === "warning") return "warning";
        return "info";
    }

    /**
     * View-only choice of the leading severity icon for an alert banner:
     * the ``alert`` glyph for warning/critical, the ``clock`` glyph for info.
     * @param {string} level raw alert level
     * @returns {string} env.icon name ("alert" | "clock")
     */
    levelIcon(level) {
        return (level === "warning" || level === "critical") ? "alert" : "clock";
    }
}
