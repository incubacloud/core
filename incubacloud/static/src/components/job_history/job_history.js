import { Component, useState } from "@odoo/owl";
import { useService } from "@web/core/utils/hooks";
import { _t } from "@web/core/l10n/translation";
import { parseUTC } from "../../utils/dates";
import { SearchSelect } from "../search_select/search_select";

const ALL_STATES = ["pending", "enqueued", "wait_dependencies", "started", "done", "failed", "cancelled"];
const ACTIVE_STATES = ["pending", "enqueued", "wait_dependencies", "started"];

export class JobHistory extends Component {
    static template = "incubacloud.JobHistory";
    static components = { SearchSelect };
    static props = {
        job_id: { type: [Number, Boolean], optional: true },
        instance_id: { type: [Number, Boolean], optional: true },
        host_id: { type: [Number, Boolean], optional: true },
        embedded: { type: Boolean, optional: true },
    };

    setup() {
        const jobId = this.props.job_id || null;
        const instanceId = this.props.instance_id || null;
        const hostId = this.props.host_id || null;
        this.state = useState({
            jobs: [],
            hosts: [],
            instances: [],
            users: [],
            loading: true,
            alertMode: !!jobId,
            preClaim: false,
            filter: {
                include_pre_claim: false,
                states: [],
                host_id: hostId,
                user_id: null,
                date_from: "",
                date_to: "",
                job_category: jobId ? "all" : "operational",
                job_id: jobId,
                instance_id: instanceId,
            },
            ganttHours: 24,
        });

        this.orm = useService("orm");
        this.loadHistory();
    }

    // ───────────── Data ─────────────

    async loadHistory() {
        this.state.loading = true;
        const filters = this._buildFilters();
        const result = await this.orm.call("cloud.job", "load_history", [filters]);
        this.state.jobs = result.jobs;
        this.state.hosts = result.hosts;
        this.state.instances = result.instances || [];
        this.state.users = result.users || [];
        this.state.preClaim = result.preClaim || false;
        this.state.loading = false;
    }

    // ───────────── SearchSelect options ─────────────

    get hostOptions() {
        return this.state.hosts.map(h => ({ value: h.id, label: h.name }));
    }

    get instanceOptions() {
        return this.state.instances.map(i => ({ value: i.id, label: i.name }));
    }

    get userOptions() {
        return this.state.users.map(u => ({ value: u.id, label: u.name }));
    }

    setHost(value) {
        this.state.filter.host_id = value ? parseInt(value) : null;
    }

    setInstance(value) {
        this.state.filter.instance_id = value ? parseInt(value) : null;
    }

    setUser(value) {
        this.state.filter.user_id = value ? parseInt(value) : null;
    }

    _buildFilters() {
        const f = this.state.filter;
        const filters = { job_category: f.job_category };
        if (f.job_id) filters.job_id = f.job_id;
        if (f.states.length) filters.states = f.states;
        if (f.host_id) filters.host_id = f.host_id;
        if (f.date_from) filters.date_from = f.date_from;
        if (f.date_to) filters.date_to = f.date_to;
        if (f.instance_id) filters.instance_id = f.instance_id;
        if (f.user_id) filters.user_id = f.user_id;
        if (f.include_pre_claim) filters.include_pre_claim = true;
        // When opened from a host or instance, restrict to that scope
        if (this.props.host_id) filters.apply_to = 'host';
        if (this.props.instance_id) filters.apply_to = 'instance';
        return filters;
    }

    clearAlertMode() {
        this.state.alertMode = false;
        this.state.filter.job_id = null;
        this.state.filter.job_category = "operational";
        this.loadHistory();
    }

    resetFilters() {
        const hostId = this.props.host_id || null;
        const instanceId = this.props.instance_id || null;
        this.state.filter.states = [];
        this.state.filter.host_id = hostId;
        this.state.filter.user_id = null;
        this.state.filter.date_from = "";
        this.state.filter.date_to = "";
        this.state.filter.job_category = "operational";
        this.state.filter.job_id = null;
        this.state.filter.instance_id = instanceId;
        this.state.filter.include_pre_claim = false;
        this.state.alertMode = false;
        this.loadHistory();
    }

    resetFilter() {
        this.resetFilters();
    }

    /**
     * Show or hide the jobs that predate this instance's handover.
     *
     * Only reachable when the backend reported a cutoff, so the flag
     * stays off for every instance that owns its whole history.
     */
    togglePreClaim() {
        this.state.filter.include_pre_claim = !this.state.filter.include_pre_claim;
        this.loadHistory();
    }

    // ───────────── Filters ─────────────

    toggleState(s) {
        const idx = this.state.filter.states.indexOf(s);
        if (idx >= 0) {
            this.state.filter.states.splice(idx, 1);
        } else {
            this.state.filter.states.push(s);
        }
    }

    isStateActive(s) {
        return this.state.filter.states.length === 0 || this.state.filter.states.includes(s);
    }

    applyFilter() {
        this.loadHistory();
    }

    setCategory(cat) {
        this.state.filter.job_category = cat;
        this.loadHistory();
    }

    onDateFromChange(ev) {
        this.state.filter.date_from = ev.target.value;
    }

    onDateToChange(ev) {
        this.state.filter.date_to = ev.target.value;
    }

    setGanttWindow(hours) {
        this.state.ganttHours = hours;
    }

    // ───────────── Gantt ─────────────

    get ganttJobs() {
        const now = Date.now();
        const windowMs = this.state.ganttHours * 3600 * 1000;
        const rangeEnd = now;
        const rangeStart = rangeEnd - windowMs;

        return this.state.jobs
            .map(job => {
                const start = parseUTC(job.create_date).getTime();
                const isActive = ACTIVE_STATES.includes(job.state);
                const end = (isActive || !job.duration_s)
                    ? (isActive ? now : start + 1000)
                    : start + job.duration_s * 1000;

                const left = Math.max(0, (start - rangeStart) / windowMs * 100);
                const right = Math.min(100, (end - rangeStart) / windowMs * 100);
                const width = Math.max(0.4, right - left);

                return { ...job, ganttLeft: left, ganttWidth: width, _inRange: right > 0 && left < 100 };
            })
            .filter(j => j._inRange)
            .slice(0, 50);
    }

    get ganttTicks() {
        const count = Math.min(this.state.ganttHours, 12);
        const step = this.state.ganttHours / count;
        const now = Date.now();
        const ticks = [];
        for (let i = 0; i <= count; i++) {
            const ms = now - (this.state.ganttHours - i * step) * 3600 * 1000;
            const d = new Date(ms);
            const label = d.getHours().toString().padStart(2, "0") + ":" +
                          d.getMinutes().toString().padStart(2, "0");
            ticks.push({ pct: (i / count * 100).toFixed(1), label });
        }
        return ticks;
    }

    // ───────────── Formatters ─────────────

    formatDuration(s) {
        if (!s || s <= 0) return "—";
        if (s < 60) return `${s}s`;
        const m = Math.floor(s / 60);
        const sec = s % 60;
        if (m < 60) return sec > 0 ? `${m}m ${sec}s` : `${m}m`;
        const h = Math.floor(m / 60);
        const min = m % 60;
        return min > 0 ? `${h}h ${min}m` : `${h}h`;
    }

    formatDate(dateStr) {
        if (!dateStr) return "—";
        const d = parseUTC(dateStr);
        return d.toLocaleString([], {
            month: "2-digit", day: "2-digit",
            hour: "2-digit", minute: "2-digit",
        });
    }

    stateName(state) {
        return {
            pending: _t("Pending"), enqueued: _t("Queued"),
            wait_dependencies: _t("Waiting"), started: _t("Running"),
            done: _t("Done"), failed: _t("Failed"), cancelled: _t("Cancelled"),
        }[state] || state;
    }

    stateLabel(state) {
        return {
            pending: _t("Pending"), enqueued: _t("Queued"), wait_dependencies: _t("Waiting"),
            started: _t("Running"), done: _t("Done"), failed: _t("Failed"), cancelled: _t("Cancelled"),
        }[state] || state;
    }

    /**
     * View-only mapping of a raw job ``state`` to the Relay state-class used by
     * the timeline dot (``rl-tl-dot``) and the bare status pill (``rl-pill``):
     * ``done`` / ``failed`` / ``queued`` (amber, pending-like) / ``running``.
     * No business logic — purely picks the CSS modifier for the chosen state.
     * @param {string} state raw cloud.job state
     * @returns {string} one of "done" | "failed" | "queued" | "running"
     */
    ganttDotClass(state) {
        return {
            done: "done",
            failed: "failed",
            cancelled: "failed",
            started: "running",
            pending: "queued",
            enqueued: "queued",
            wait_dependencies: "queued",
        }[state] || "queued";
    }

    // ───────────── Actions ─────────────

    openLog(job) {
        window.open(`/cloud/log/${job.id}`, "_blank");
    }

    get allStateKeys() {
        return ALL_STATES;
    }
}
