import { Component, useState, onWillStart, onWillUpdateProps, useEnv } from "@odoo/owl";
import { rpc } from "@web/core/network/rpc";
import { useService } from "@web/core/utils/hooks";
import { _t } from "@web/core/l10n/translation";
import { tagStyle, tagDotStyle } from "../tag_selector/tag_selector";
import { IcModal } from "../ic_modal/ic_modal";

export class ProjectSidebar extends Component {
    static template = "incubacloud.ProjectSidebar";
    static components = { IcModal };
    static props = {
        projectId:          { type: Number },
        currentRoute:       { type: String },
        selectedInstanceId: { type: Number },
    };

    setup() {
        this.env = useEnv();
        // Reactive subscription to the shared project store. The store
        // owns the cloud_jobs bus subscription, debouncing, in-flight
        // guard and cache — see ``store/project_store.js``. The
        // sidebar reads; it never fetches.
        this.store = this.env.projectStore;
        this.storeState = useState(this.store.state);
        this.ui = useState({
            search: "",
            cloneModal: null,  // { instanceId, name, loading, error }
        });

        this.orm = useService("orm");

        onWillStart(async () => {
            await this.store.load(this.props.projectId);
            this._afterLoad();
        });
        onWillUpdateProps(async (next) => {
            if (next.projectId !== this.props.projectId) {
                await this.store.load(next.projectId);
                this._afterLoad();
            }
        });
    }

    _afterLoad() {
        this.env.setProjectName?.(this.storeState.data?.project?.name || "");
        // Auto-redirect: if landing on project_detail with instances,
        // navigate to the first one (production > staging).
        if (
            this.props.currentRoute === "project_detail"
            && this.instances.length
        ) {
            const first = this.store.getNextInstance(null);
            if (first) {
                this.env.navigate("instance_detail", {
                    project_id: this.props.projectId,
                    instance_id: first.id,
                });
            }
        }
    }

    get loading() {
        return this.storeState.loading && !this.storeState.data;
    }

    get projectName() {
        return this.storeState.data?.project?.name || "";
    }

    get odooVersion() {
        return this.storeState.data?.project?.odoo_version || "";
    }

    get instances() {
        return Object.values(this.storeState.data?.instances || {});
    }

    get grouped() {
        const groups = { production: [], staging: [] };
        for (const inst of this.instances) {
            const env = inst.environment || "staging";
            if (groups[env]) groups[env].push(inst);
        }
        return groups;
    }

    _matchesSearch(inst, q) {
        if (!q) return true;
        if ((inst.name || "").toLowerCase().includes(q)) return true;
        return (inst.tags || []).some(
            t => (t.name || "").toLowerCase().includes(q),
        );
    }

    get filteredGrouped() {
        const q = (this.ui.search || "").trim().toLowerCase();
        const out = { production: [], staging: [] };
        for (const env of Object.keys(out)) {
            out[env] = (this.grouped[env] || []).filter(
                i => this._matchesSearch(i, q),
            );
        }
        return out;
    }

    onSearchInput(ev) {
        this.ui.search = ev.target.value || "";
    }

    tagBadgeStyle(tag) { return tagStyle(tag); }
    tagDotStyle(tag) { return tagDotStyle(tag); }

    get selectedId() {
        return this.props.selectedInstanceId || null;
    }

    get activeSection() {
        const r = this.props.currentRoute;
        if (r === "instance_detail" || r === "create_instance") return "";
        if (r === "project_settings") return "project_settings";
        // Don't highlight Settings when onboarding is shown (no instances)
        if (r === "project_detail" && !this.instances.length) return "";
        return r;
    }

    goBack() {
        this.env.navigate("projects");
    }

    selectInstance(inst) {
        this.env.navigate("instance_detail", {
            project_id: this.props.projectId,
            instance_id: inst.id,
        });
    }

    goProjectSettings() {
        this.env.navigate("project_settings", { project_id: this.props.projectId });
    }

    createInstance(environment) {
        this.env.navigate("create_instance", {
            project_id: this.props.projectId,
            environment,
        });
    }

    envLabel(env) {
        return { production: _t("Production"), staging: _t("Staging") }[env] || env;
    }

    statusDot(inst) {
        if (inst.state === "deploying" || inst.state === "deleting") {
            return "dot-provisioning";
        }
        if (!inst.deployed) return "dot-neutral";
        if (inst.running) return "dot-ok";
        if (inst.status === "error") return "dot-error";
        if (inst.stop_is_expected) return "dot-asleep";
        return "dot-stopped";
    }

    /**
     * Map an instance to the matching ``rl-pill`` status CSS class, for the
     * bare status dot shown in each context-sidebar item. View-helper only
     * (no state change); mirrors the dot semantics of ``statusDot``.
     * @param {Object} inst instance record from the project store
     * @returns {string} an ``rl-pill`` status modifier class
     */
    statusPill(inst) {
        if (inst.state === "deploying" || inst.state === "deleting") {
            return "provisioning";
        }
        if (!inst.deployed) return "draft";
        if (inst.running) return "running";
        if (inst.status === "error") return "crashed";
        if (inst.stop_is_expected) return "asleep";
        return "stopped";
    }

    cloneToStaging(inst) {
        this.ui.cloneModal = {
            instanceId: inst.id,
            name: inst.name + '-staging',
            loading: false,
            error: null,
        };
    }

    async doClone() {
        const m = this.ui.cloneModal;
        if (!m || m.loading || !m.name.trim()) return;
        m.loading = true;
        m.error = null;
        try {
            const res = await rpc("/cloud/clone_to_staging", {
                instance_id: m.instanceId,
                staging_name: m.name.trim(),
            });
            if (!res.ok) {
                m.error = res.error;
                m.loading = false;
                return;
            }
            this.ui.cloneModal = null;
            // Force-refresh the store so the new staging instance is
            // visible to the destination route before navigating.
            await this.store.load(this.props.projectId);
            this.env.navigate("instance_detail", {
                project_id: this.props.projectId,
                instance_id: res.staging_id,
            });
        } catch (e) {
            m.error = e.data?.message || e.message || _t("Clone failed.");
            m.loading = false;
        }
    }
}
