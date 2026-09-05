import {
  Component,
  useState,
  onWillStart,
  onMounted,
  onWillUnmount,
  useEnv,
} from "@odoo/owl";
import {rpc} from "@web/core/network/rpc";
import {useService} from "@web/core/utils/hooks";
import {_t} from "@web/core/l10n/translation";
import {RepoEditor} from "../repo_editor/repo_editor";
import {parseUTC} from "../../utils/dates";
import {useSafePoll} from "../../utils/use_safe_poll";
import {useVisibilityRefresh} from "../../utils/use_visibility_refresh";
import {useDebouncedBus} from "../../utils/use_debounced_bus";
import {useNavGuard} from "../../utils/use_nav_guard";
import {useFormValidation} from "../../utils/use_form_validation";
import {required, instanceName, portRange, when} from "../../utils/validators";
import {PasswordInput} from "../password_input/password_input";
import {TagSelector, tagStyle, tagDotStyle} from "../tag_selector/tag_selector";
import {IcConfirmDialog} from "../ic_confirm_dialog/ic_confirm_dialog";
import {IcModal} from "../ic_modal/ic_modal";
import {SearchSelect} from "../search_select/search_select";
import {RlSelect} from "../rl_select/rl_select";
import {IcPager} from "../ic_pager/ic_pager";
import {JobsMixin} from "./instance_detail_jobs";
import {MoveMixin} from "./instance_detail_move";
import {SyncMixin} from "./instance_detail_sync";
import {BackupsMixin} from "./instance_detail_backups";
import {AccessMixin} from "./instance_detail_access";
import {RestoreUploadMixin} from "./instance_detail_restore";
import {RefreshMixin} from "./instance_detail_refresh";
import {AuditMixin} from "./instance_detail_audit";
import { confirmVia } from "../../utils/use_confirm";

const PG_VERSIONS = ["14", "15", "16", "17", "18"];

// ── Pip requirements helpers ─────────────────────────────────────────────────

function _parseReqLine(line) {
  const stripped = line.split("#")[0].trim();
  if (!stripped) return null;
  const m = stripped.match(/^([A-Za-z0-9_.-]+)/);
  if (!m) return null;
  const name = m[1].toLowerCase();
  const markerM = stripped.match(/;(.+)/);
  const marker = markerM ? markerM[1].trim().toLowerCase() : "";
  return {name, raw: stripped, key: marker ? `${name}|${marker}` : name};
}

function _formatSource(url, branch) {
  const m = (url || "").match(/github\.com[:/](.+)/);
  const name = m ? m[1].replace(/\.git$/, "") : (url || "").replace(/\/$/, "");
  return branch ? `${name} (${branch})` : name;
}

function _escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function _buildPkgMap(text) {
  const pkgMap = {};
  const re =
    /<<<<<<< (?<eSrc>[^\n]*)\n(?<eLine>[^\n]*)\n=======\n(?<iLine>[^\n]*)\n>>>>>>> (?<iSrc>[^\n]*)/g;
  let m;
  while ((m = re.exec(text || "")) !== null) {
    const parsed = _parseReqLine(m.groups.eLine.trim());
    if (parsed) {
      pkgMap[parsed.key] = {
        type: "conflict",
        spec: parsed.raw,
        name: parsed.name,
        existingSrc: m.groups.eSrc.trim(),
        block: m[0],
      };
    }
  }
  const cleanOnly = (text || "").replace(
    /<<<<<<< [^\n]*\n[^\n]*\n=======\n[^\n]*\n>>>>>>> [^\n]*/g,
    ""
  );
  for (const line of cleanOnly.split("\n")) {
    const parsed = _parseReqLine(line);
    if (parsed && !(parsed.key in pkgMap)) {
      pkgMap[parsed.key] = {
        type: "clean",
        spec: parsed.raw,
        name: parsed.name,
        block: null,
      };
    }
  }
  return pkgMap;
}

/**
 * Merge incomingText into existingText with git-style conflict markers.
 * Returns { content, conflicts: [{name, existing, existingSource, incoming, incomingSource}] }
 */
function mergeRequirements(existingText, incomingText, repoUrl, repoBranch) {
  const sourceLabel = _formatSource(repoUrl, repoBranch);
  const pkgMap = _buildPkgMap(existingText);
  let newText = existingText || "";
  const added = [];
  const conflicts = [];

  for (const line of (incomingText || "").split("\n")) {
    const parsed = _parseReqLine(line);
    if (!parsed) continue;
    const {name, raw, key} = parsed;

    if (!(key in pkgMap)) {
      added.push(raw);
      pkgMap[key] = {type: "clean", spec: raw, name, block: null};
    } else if (pkgMap[key].spec === raw) {
      // exact duplicate — skip
    } else if (pkgMap[key].type === "conflict") {
      const oldBlock = pkgMap[key].block;
      const existingSrc = pkgMap[key].existingSrc;
      const existingSpec = pkgMap[key].spec;
      const newBlock = `<<<<<<< ${existingSrc}\n${existingSpec}\n=======\n${raw}\n>>>>>>> ${sourceLabel}`;
      newText = newText.replace(oldBlock, newBlock);
      pkgMap[key].block = newBlock;
      conflicts.push({
        name,
        existing: existingSpec,
        existingSource: existingSrc,
        incoming: raw,
        incomingSource: sourceLabel,
      });
    } else {
      const existingSpec = pkgMap[key].spec;
      const newBlock = `<<<<<<< existing\n${existingSpec}\n=======\n${raw}\n>>>>>>> ${sourceLabel}`;
      // Function form of replace: bypasses the ``$&`` / ``$1`` /
      // ``$$`` substitution rules that would otherwise corrupt
      // the merged text when ``newBlock`` contains a repo URL or
      // branch name with literal ``$`` characters.
      newText = newText.replace(
        new RegExp("^" + _escapeRegex(existingSpec) + "$", "m"),
        () => newBlock
      );
      pkgMap[key] = {
        type: "conflict",
        spec: existingSpec,
        name,
        existingSrc: "existing",
        block: newBlock,
      };
      conflicts.push({
        name,
        existing: existingSpec,
        existingSource: "existing",
        incoming: raw,
        incomingSource: sourceLabel,
      });
    }
  }

  if (added.length) {
    const base = newText.trimEnd();
    newText = base + (base ? "\n" : "") + added.join("\n");
  }

  return {content: newText, conflicts};
}

/**
 * Apply user-chosen resolutions to pip_dependencies text.
 * choices: { [packageName]: chosenSpec }
 */
function applyPipResolutions(text, choices) {
  return (text || "").replace(
    /<<<<<<< [^\n]*\n([^\n]*)\n=======\n[^\n]*\n>>>>>>> [^\n]*/g,
    (block, existingLine) => {
      const parsed = _parseReqLine(existingLine.trim());
      return parsed && parsed.name in choices ? choices[parsed.name] : block;
    }
  );
}

// Responsibility mixins, split out in Fase 4 / B3. Order is
// irrelevant: no mixin overrides another's methods.
export class InstanceDetail extends JobsMixin(
  MoveMixin(
  SyncMixin(
  BackupsMixin(
  AccessMixin(
  RestoreUploadMixin(
  RefreshMixin(
  AuditMixin(
  Component)))))))) {
  static props = {
    instance_id: {type: Number, optional: true},
    project_id: {type: Number},
    environment: {type: String, optional: true},
    embedded: {type: Boolean, optional: true},
  };
  static template = "incubacloud.InstanceDetail";
  static components = {
    RepoEditor,
    PasswordInput,
    TagSelector,
    IcConfirmDialog,
    IcModal,
    SearchSelect,
    RlSelect,
    IcPager,
  };

  get isCreate() {
    return !this.props.instance_id;
  }

  /** Rows per page for the server-paginated lists (backups, audit log). */
  get pageSize() {
    return 20;
  }

  get hasUnsavedChanges() {
    return this._savedForm && JSON.stringify(this.state.form) !== this._savedForm;
  }

  /**
   * Options for the host RlSelect: maps each available host to a
   * {value, label} entry where the label shows the host name plus its
   * free CPU / RAM, keeping numeric ids as the option value.
   * @returns {{value: number, label: string}[]} host select options
   */
  get hostOptions() {
    return this.state.hosts.map((h) => ({
      value: h.id,
      label: `${h.name} (${h.available_cpus} CPU / ${h.available_ram_gb} GB free)`,
    }));
  }

  /**
   * Options for the backup-backend RlSelect: maps each available backup
   * backend to a {value, label} entry (numeric id as value, name as label).
   * @returns {{value: number, label: string}[]} backup backend select options
   */
  get backupBackendOptions() {
    return this.state.backupBackends.map((bb) => ({
      value: bb.id,
      label: bb.name,
    }));
  }

  setup() {
    this.env = useEnv();
    this.orm = useService("orm");
    this.pgVersions = PG_VERSIONS;

    this.state = useState({
      tab: "overview",
      loading: true,
      saving: false,
      error: null,
      hosts: [],
      autoassignEnabled: false,
      backupBackends: [],
      langs: [],
      langsLoading: false,
      _initialLangId: null,
      inst: null,
      form: {},
      selectedTags: [],
      allTags: [],
      langSearch: "",
      langOpen: false,
      repoSearch: "",
      pipDeps: "",
      aptDeps: "",
      pipConflictModal: null, // { conflicts, choices }
      // Metrics tab. The config is fetched once per visit; the access
      // log is read on demand, because it is live data from the host and
      // a stale copy would be worse than none during an incident.
      metricsCfg: { loading: true, enabled: false, baseUrl: "" },
      accessLog: {
        loading: false, loaded: false, error: "",
        entries: [], summary: { by_status: [], top_clients: [], top_paths: [] },
      },
      // has_* flags — whether a password is currently stored server-side
      has_odoo_admin_password: false,
      has_postgres_password: false,
      has_smtp_relay_password: false,
      // sync modal
      syncModal: null, // { diff, actions, loading, applying, error }
      // action-related state
      actionLoading: false,
      confirmDialog: null,
      // move-to-host action
      movePicker: null, // { targetHostId, loading, loaded }
      moveHosts: [],
      // { sourceId, source, neutralize, loading, loaded, error, submitting }
      refreshDialog: null,
      refreshSources: [],
      conflictBlocked: null,
      restoreDialog: null,
      connectDialog: null,
      shellDialog: null,
      // activity (jobs)
      activeJobs: [],
      recentJobs: [],
      jobsTotal: 0,
      jobsLoading: false,
      // backups
      backupsLoading: false,
      backupsData: null,
      backupsError: null,
      backupsJobId: null,
      backupsOffset: 0,
      downloadModal: null, // { time, type, loading }
      createBackupModal: null, // { withFilestore, loading }
      restoreBackupModal: null, // { time, confirmName, loading }
      // audit log
      auditLog: [],
      auditLogLoading: false,
      auditOffset: 0,
      auditTotal: 0,
      auditFilter: {q: "", action: "", date_from: "", date_to: ""},
      auditActions: [],
      auditPurging: false,
    });

    this._pollTimer = null;
    this._savedForm = null;

    this.validator = useFormValidation(() => ({
      name: [required(_t("Instance name is required")), instanceName()],
      host_id: [
        when(
          () => !this.state.autoassignEnabled,
          required(_t("Host is required when auto-assign is disabled"))
        ),
      ],
      smtp_relay_port: [portRange()],
    }));
    this._busService = useService("bus_service");
    // Shared guard for every recursive setTimeout(poll, …) in this
    // component. Registers onWillUnmount so zombie ticks can't
    // write into a destroyed component's state.
    this._safePoll = useSafePoll();

    // Debounced refresh of THIS instance's deeper detail
    // (jobs list, repos, etc. via /cloud/get_instance). The
    // project-level refresh — including sibling instances' status
    // dots — is owned by ``env.projectStore``, which subscribes
    // to the same bus once for the whole app. We do not call
    // ``refreshSidebar`` here: the store reacts to the same event
    // independently and the explicit hop would only duplicate the
    // /cloud/get_project_full RPC.
    const triggerRefresh = useDebouncedBus(() => {
      if (!this._destroyed) this._silentRefresh();
    });
    // The instance filter runs HERE, before the debounce — never
    // inside the callback. ``useDebouncedBus`` is last-write-wins on
    // its argument, so a matching event arriving in the same 300 ms
    // window as a non-matching one would be discarded if we branched
    // downstream. Filtering at the subscription keeps every event we
    // care about.
    //
    // The bus payload carries the target, so this used to cost an
    // ``orm.call("cloud.job", "load_jobs")`` per event — for every
    // job in the fleet, not just ours — purely to read
    // ``job.instance_id``. Same predicate, no round-trip.
    this._onJobUpdate = (payload) => {
      if (payload?.instance_id !== this.props.instance_id) return;
      triggerRefresh(payload.id);
    };

    onWillStart(() => this.load());
    onMounted(() => {
      if (!this.isCreate) {
        this._busService.subscribe("cloud_jobs", this._onJobUpdate);
      }
    });
    onWillUnmount(() => {
      this._destroyed = true;
      this._busService.unsubscribe("cloud_jobs", this._onJobUpdate);
    });
    // Nav guard owns the ``beforeunload`` listener now — the old
    // direct listener was superseded to avoid duplicate handlers.
    useNavGuard(
      () => this.hasUnsavedChanges,
      (opts) => this._confirm(opts)
    );
    // Bus covers the happy path; ``visibilitychange`` refresh catches
    // events dropped while the tab was backgrounded.
    useVisibilityRefresh(() => {
      if (!this.isCreate && !this._destroyed) this._silentRefresh();
    });
  }

  async _silentRefresh() {
    try {
      const inst = await rpc("/cloud/get_instance", {
        instance_id: this.props.instance_id,
      });
      this.state.inst = inst;
      this.state.activeJobs = inst.activeJobs || [];
      this.state.recentJobs = inst.recentJobs || [];
      this.state.jobsTotal = inst.jobsTotal || 0;
      // Patch the project store so the sidebar reflects this
      // instance's fresh status without waiting for its own bus
      // refresh tick.
      this.env.projectStore?.updateInstance(this.props.instance_id, inst);
    } catch (_e) {
      console.debug("Silent refresh failed:", _e);
    }
  }

  timeAgo(dateStr) {
    if (!dateStr) return "";
    const now = new Date();
    const d = parseUTC(dateStr);
    const secs = Math.floor((now - d) / 1000);
    if (secs < 60) return "just now";
    const mins = Math.floor(secs / 60);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
  }

  formatDate(dateStr) {
    if (!dateStr) return "";
    const d = parseUTC(dateStr);
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(
      d.getHours()
    )}:${pad(d.getMinutes())}`;
  }

  goResolveAlert(ev) {
    ev.stopPropagation();
    this.env.toggleSlideOver("alerts");
  }

  _applyInstanceData(inst, hosts, backends) {
    this.state.hosts = (hosts || []).filter(
      (h) => h.status === "compatible" && h.traefik_deployed
    );
    this.state.backupBackends = backends || [];
    this.state.inst = inst;
    this.state.activeJobs = inst.activeJobs || [];
    this.state.recentJobs = inst.recentJobs || [];
    this.state.jobsTotal = inst.jobsTotal || 0;
    if (inst.odoo_initial_lang) {
      this.state._initialLangId = inst.odoo_initial_lang;
      this.state.langSearch = "(loading…)";
    }
    this.state.has_odoo_admin_password = inst.has_odoo_admin_password || false;
    this.state.has_postgres_password = inst.has_postgres_password || false;
    this.state.has_smtp_relay_password = inst.has_smtp_relay_password || false;
    this.state.pipDeps = inst.pip_dependencies || "";
    this.state.aptDeps = inst.apt_dependencies || "";
    this.state.form = {
      name: inst.name || "",
      environment: inst.environment || "staging",
      host_id: inst.host_id || null,
      odoo_version: inst.odoo_version || 19.0,
      odoo_initial_lang: inst.odoo_initial_lang || null,
      odoo_admin_password: "",
      odoo_proxy: inst.odoo_proxy || "traefik",
      postgres_version: inst.postgres_version || "17",
      postgres_dbname: inst.postgres_dbname || "",
      postgres_username: inst.postgres_username || "",
      postgres_password: "",
      domains: (inst.domains || []).map((d) => ({...d})),
      smtp_relay_host: inst.smtp_relay_host || "",
      smtp_relay_port: inst.smtp_relay_port || 587,
      smtp_relay_security: inst.smtp_relay_security || "starttls",
      smtp_relay_user: inst.smtp_relay_user || "",
      smtp_relay_password: "",
      odoo_conf: inst.odoo_conf || "",
      odoo_memory_limit: inst.odoo_memory_limit || "2g",
      odoo_cpus: inst.odoo_cpus || 2.0,
      db_memory_limit: inst.db_memory_limit || "1g",
      db_cpus: inst.db_cpus || 1.0,
      backup_memory_limit: inst.backup_memory_limit || "512m",
      backup_cpus: inst.backup_cpus || 0.5,
      smtp_memory_limit: inst.smtp_memory_limit || "256m",
      smtp_cpus: inst.smtp_cpus || 0.25,
      backup_backend_id: inst.backup_backend_id || null,
      auto_rebuild: inst.auto_rebuild || false,
      auto_update: inst.auto_update !== false,
      repos: (inst.repos || []).map((r) => ({...r})),
    };
    this.state.selectedTags = [...(inst.tags || [])];
    this.state.allTags = [...(inst.all_tags || [])];
    this.state.backupsData = null;
    this.state.backupsError = null;
    this._savedForm = JSON.stringify(this.state.form);
  }

  async load() {
    this.state.loading = true;
    try {
      if (this.isCreate) {
        this.state.tab = "general";
        const [hostsResp, project, backends] = await Promise.all([
          rpc("/cloud/get_hosts"),
          rpc("/cloud/get_project", {project_id: this.props.project_id}),
          rpc("/cloud/get_backup_backends", {}),
        ]);
        this.state.backupBackends = backends?.items || backends || [];
        const allHosts = hostsResp.hosts || hostsResp || [];
        this.state.autoassignEnabled = !!hostsResp.autoassign_enabled;
        this.state.hosts = allHosts.filter(
          (h) => h.status === "compatible" && h.traefik_deployed
        );
        const repos = (project?.repos || []).map((r) => ({
          id: null,
          url: r.url || "",
          branch: r.branch || "main",
          addons: "",
          excludes: "",
          commit_sha: r.commit_sha || "",
        }));
        this.state.pipDeps = project?.pip_dependencies || "";
        this.state.aptDeps = project?.apt_dependencies || "";
        try {
          const tagsRes = await rpc("/cloud/get_tags", {scope: "instance"});
          this.state.allTags = tagsRes.tags || [];
        } catch (_e) {
          /* noop */
        }
        this.state.form = {
          name: "",
          environment: this.props.environment || "staging",
          host_id: null,
          odoo_version: parseFloat(project?.odoo_version) || 19.0,
          odoo_initial_lang: null,
          odoo_admin_password: "",
          odoo_proxy: "traefik",
          postgres_version: "17",
          postgres_username: "odoo",
          postgres_password: "",
          domains: [],
          smtp_relay_host: "",
          smtp_relay_port: 587,
          smtp_relay_security: "starttls",
          smtp_relay_user: "",
          smtp_relay_password: "",
          odoo_conf: "",
          odoo_memory_limit: "2g",
          odoo_cpus: 2.0,
          db_memory_limit: "1g",
          db_cpus: 1.0,
          backup_memory_limit: "512m",
          backup_cpus: 0.5,
          smtp_memory_limit: "256m",
          smtp_cpus: 0.25,
          backup_backend_id: project?.backup_backend_id || null,
          auto_rebuild: false,
          auto_update: true,
          repos,
        };
        this._savedForm = JSON.stringify(this.state.form);
      } else {
        // Try the project store first — instant switch when
        // navigating between instances of the same project.
        const storeState = this.env.projectStore?.state;
        if (storeState?.projectId === this.props.project_id && storeState.data) {
          const cached = storeState.data.instances[this.props.instance_id];
          if (cached) {
            this._applyInstanceData(
              cached,
              storeState.data.hosts,
              storeState.data.backup_backends
            );
            this.state.loading = false;
            return;
          }
        }
        // Store miss — fall back to server.
        const inst = await rpc("/cloud/get_instance", {
          instance_id: this.props.instance_id,
        });
        this._applyInstanceData(inst, this.state.hosts, this.state.backupBackends);
      }
    } catch (e) {
      this.state.error = this.isCreate
        ? _t("Failed to load project data.")
        : _t("Failed to load instance.");
    } finally {
      this.state.loading = false;
    }
  }

  setTab(tab) {
    this.state.tab = tab;
    if (tab === "backups" && !this.state.backupsData && !this.state.backupsLoading) {
      this._loadBackups();
    }
    if (
      tab === "activity" &&
      !this.state.auditLog.length &&
      !this.state.auditLogLoading
    ) {
      this._loadAuditLog();
    }
    if (tab === "metrics") {
      this._loadMetricsConfig();
      if (!this.state.accessLog.loaded && !this.state.accessLog.loading) {
        this.loadAccessLog();
      }
    }
  }

  /**
   * True when this panel's own operator edits the observability
   * settings, so a stub pointing at Settings is actionable advice.
   *
   * @see Monitoring#canConfigure — same axis, same reason for reading it
   * from the boot config rather than from the metrics route.
   */
  get canConfigureObservability() {
    return this.env.features?.observability?.configure !== false;
  }

  /**
   * Fetch whether observability is on and where the dashboards live.
   *
   * Deliberately narrow: the backend never hands the browser the metrics
   * credentials, only the public Grafana URL.
   */
  async _loadMetricsConfig() {
    if (!this.state.metricsCfg.loading && this.state.metricsCfg.fetched) {
      return;
    }
    this.state.metricsCfg.loading = true;
    try {
      const cfg = await rpc("/cloud/monitoring/config", {});
      this.state.metricsCfg = {
        loading: false,
        fetched: true,
        enabled: !!cfg.enabled,
        baseUrl: cfg.grafana_base_url || "",
      };
    } catch {
      this.state.metricsCfg = {
        loading: false, fetched: true, enabled: false, baseUrl: "",
      };
    }
  }

  /**
   * Read this instance's recent requests from the proxy on its host.
   *
   * Answers what the charts cannot: which client IPs are hitting it and
   * on which paths. Nothing is cached server-side, so every refresh is
   * a live read.
   */
  async loadAccessLog() {
    this.state.accessLog.loading = true;
    this.state.accessLog.error = "";
    try {
      const res = await rpc("/cloud/instance/access_log", {
        instance_id: this.props.instance_id,
      });
      if (!res.ok) {
        this.state.accessLog.error = res.error || _t("Could not read the proxy log.");
        this.state.accessLog.entries = [];
      } else {
        this.state.accessLog.entries = res.entries || [];
        this.state.accessLog.summary = res.summary || {
          by_status: [], top_clients: [], top_paths: [],
        };
      }
    } catch (e) {
      this.state.accessLog.error =
        e?.data?.message || e?.message || _t("Could not read the proxy log.");
      this.state.accessLog.entries = [];
    } finally {
      this.state.accessLog.loading = false;
      this.state.accessLog.loaded = true;
    }
  }

  /**
   * Grafana URL for this instance's dashboard, pinned to this instance.
   *
   * The variable is a view filter, never a boundary: what a viewer may
   * see is decided by the gateway, from the credentials the datasource
   * authenticates with. Changing it by hand only moves within what that
   * account could already read.
   *
   * The host is pinned too. Container names repeat across hosts and an
   * instance name is only unique within its project, so filtering by the
   * instance alone can quietly add up series from two different machines.
   */
  get instanceDashboardUrl() {
    const base = (this.state.metricsCfg.baseUrl || "").replace(/\/+$/, "");
    if (!base || !this.state.inst) {
      return "";
    }
    const theme =
      document.documentElement.dataset.icTheme === "light" ? "light" : "dark";
    const name = encodeURIComponent(this.state.inst.name || "");
    const host = encodeURIComponent(this.state.inst.host || "");
    return `${base}/d/ic-instance/incubacloud-instance` +
      `?kiosk&theme=${theme}` +
      (host ? `&var-host=${host}` : "") +
      `&var-instance=${name}`;
  }

  /** Most recent requests first, which is how an incident is read. */
  get recentRequests() {
    return [...(this.state.accessLog.entries || [])].reverse().slice(0, 100);
  }

  onInput(field, ev) {
    this.state.form[field] = ev.target.value;
  }

  onDepsInput(ev) {
    this.state.pipDeps = ev.target.value;
  }

  onAptInput(ev) {
    this.state.aptDeps = ev.target.value;
  }

  onPasswordChange(field, value) {
    this.state.form[field] = value;
  }

  // ── Pip conflict modal ───────────────────────────────────────────────────

  openPipConflictModal(conflicts) {
    const choices = {};
    for (const c of conflicts) {
      choices[c.name] = c.existing;
    }
    this.state.pipConflictModal = {conflicts, choices};
  }

  closePipConflictModal() {
    this.state.pipConflictModal = null;
  }

  setPipChoice(name, spec) {
    if (this.state.pipConflictModal) {
      this.state.pipConflictModal.choices[name] = spec;
    }
  }

  confirmPipResolve() {
    const {choices} = this.state.pipConflictModal;
    this.state.pipConflictModal = null;
    this.state.pipDeps = applyPipResolutions(this.state.pipDeps, choices);
  }

  onHostSelect(ev) {
    const id = parseInt(ev.target.value);
    this.state.form.host_id = id || null;
  }

  onVersionSelect(ev) {
    this.state.form.odoo_version = parseFloat(ev.target.value);
  }

  onPgSelect(ev) {
    this.state.form.postgres_version = ev.target.value;
  }

  onEnvSelect(ev) {
    this.state.form.environment = ev.target.value;
  }

  // ── Domain management ──────────────────────────────────────────────

  addDomain() {
    this.state.form.domains.push({
      id: null,
      hostname: "",
      redirect_to: "",
      cert_resolver: "letsencrypt",
      redirect_permanent: false,
    });
  }

  removeDomain(idx) {
    this.state.form.domains.splice(idx, 1);
  }

  onDomainChange(idx, field, value) {
    this.state.form.domains[idx][field] = value;
  }

  onBackupBackendSelect(ev) {
    const val = ev.target.value;
    this.state.form.backup_backend_id = val ? parseInt(val) : null;
  }

  async _ensureLangs() {
    if (this.state.langs.length) return;
    this.state.langsLoading = true;
    try {
      const langs = await rpc("/cloud/get_langs");
      this.state.langs = langs;
      if (this.state._initialLangId) {
        const found = langs.find((l) => l.id === this.state._initialLangId);
        this.state.langSearch = found ? `${found.name} (${found.code})` : "";
        this.state._initialLangId = null;
      }
    } finally {
      this.state.langsLoading = false;
    }
  }

  get filteredLangs() {
    const q = this.state.langSearch.toLowerCase();
    const list = q
      ? this.state.langs.filter(
          (l) => l.name.toLowerCase().includes(q) || l.code.toLowerCase().includes(q)
        )
      : this.state.langs;
    return list.slice(0, 10);
  }

  get filteredRepos() {
    const q = (this.state.repoSearch || "").toLowerCase();
    const repos = this.state.form.repos || [];
    if (!q) return repos.map((r, i) => ({...r, _origIdx: i}));
    return repos
      .map((r, i) => ({...r, _origIdx: i}))
      .filter((r) => (r.url || "").toLowerCase().includes(q));
  }

  onLangBlur() {
    setTimeout(() => {
      this.state.langOpen = false;
    }, 150);
  }

  onLangSearchInput(ev) {
    this.state.langSearch = ev.target.value;
    this.state.langOpen = true;
    if (!ev.target.value) {
      this.state.form.odoo_initial_lang = null;
    }
  }

  selectLang(lang) {
    if (lang) {
      this.state.form.odoo_initial_lang = lang.id;
      this.state.langSearch = `${lang.name} (${lang.code})`;
    } else {
      this.state.form.odoo_initial_lang = null;
      this.state.langSearch = "";
    }
    this.state.langOpen = false;
  }

  // ── Tags ─────────────────────────────────────────────────────────────

  addTag(tag) {
    if (!this.state.selectedTags.find((t) => t.id === tag.id)) {
      this.state.selectedTags.push(tag);
    }
  }

  removeTag(tagId) {
    const idx = this.state.selectedTags.findIndex((t) => t.id === tagId);
    if (idx !== -1) this.state.selectedTags.splice(idx, 1);
  }

  async createTag(name) {
    const tag = await rpc("/cloud/create_tag", {name, scope: "instance"});
    if (!this.state.allTags.find((t) => t.id === tag.id)) {
      this.state.allTags.push(tag);
    }
    return tag;
  }

  tagBadgeStyle(tag) {
    return tagStyle(tag);
  }
  tagDotStyle(tag) {
    return tagDotStyle(tag);
  }

  async save() {
    if (this.state.saving) return;
    const {isValid, firstError} = this.validator.validate(this.state.form);
    if (!isValid) {
      this.env.toast?.error(firstError);
      return;
    }
    this.state.saving = true;
    try {
      const vals = {
        ...this.state.form,
        smtp_relay_port: parseInt(this.state.form.smtp_relay_port) || 587,
        odoo_cpus: parseFloat(this.state.form.odoo_cpus) || 0,
        db_cpus: parseFloat(this.state.form.db_cpus) || 0,
        backup_cpus: parseFloat(this.state.form.backup_cpus) || 0,
        smtp_cpus: parseFloat(this.state.form.smtp_cpus) || 0,
        pip_dependencies: this.state.pipDeps,
        apt_dependencies: this.state.aptDeps,
        tag_ids: this.state.selectedTags.map((t) => t.id),
      };
      if (this.isCreate) {
        vals.project_id = this.props.project_id;
        vals.odoo_proxy = "traefik";
        vals.postgres_dbname = "prod";
        const result = await rpc("/cloud/create_instance", {vals});
        if (result && result.blocked) {
          this.env.toast?.error(
            result.message ||
              _t("Cannot create instance: project has unresolved conflicts.")
          );
          return;
        }
        // Clear the dirty baseline before navigating so the nav
        // guard doesn't fire on the programmatic transition from
        // the create route to the new instance's detail route.
        this._savedForm = JSON.stringify(this.state.form);
        // Force-reload the store so the new instance shows up
        // in the sidebar at the destination route.
        await this.env.projectStore?.load(this.props.project_id);
        this.env.navigate("instance_detail", {
          project_id: this.props.project_id,
          instance_id: result.id,
        });
      } else {
        await rpc("/cloud/save_instance", {
          instance_id: this.props.instance_id,
          vals,
        });
        this.state.inst.name = vals.name;
        this.env.toast?.success(_t("Changes saved"));
        this._savedForm = JSON.stringify(this.state.form);
      }
    } catch (e) {
      this.env.toast?.error(
        this.isCreate
          ? e.data?.message || e.message || _t("Failed to create instance.")
          : _t("Failed to save instance.")
      );
    } finally {
      this.state.saving = false;
    }
  }

  // ── Repo management ───────────────────────────────────────────────────

  addRepo() {
    this.state.form.repos.unshift({
      id: null,
      url: "",
      branch: "",
      addons: "",
      excludes: "",
      commit_sha: "",
    });
  }

  removeRepo(idx) {
    this.state.form.repos.splice(idx, 1);
  }

  onRepoChange(idx, field, value) {
    this.state.form.repos[idx][field] = value;

    if (field === "branch" && value && this.state.form.repos[idx].url) {
      this._fetchAndMergeRequirements(this.state.form.repos[idx].url, value);
    }
  }

  async freezeAllRepos() {
    const ids = this.state.form.repos
      .filter((r) => r.id && r.url && r.branch && !r.commit_sha)
      .map((r) => r.id);
    if (!ids.length) return;
    this.state.freezingAll = true;
    try {
      const res = await rpc("/cloud/freeze_all_repos", {
        repo_ids: ids,
        model: "cloud.instance.repo",
      });
      if (res.ok) {
        for (const repo of this.state.form.repos) {
          if (res.results[repo.id]) repo.commit_sha = res.results[repo.id];
        }
      }
    } finally {
      this.state.freezingAll = false;
    }
  }

  async unfreezeAllRepos() {
    const ids = this.state.form.repos
      .filter((r) => r.id && r.commit_sha)
      .map((r) => r.id);
    if (ids.length) {
      await rpc("/cloud/unfreeze_all_repos", {
        repo_ids: ids,
        model: "cloud.instance.repo",
      });
    }
    for (const repo of this.state.form.repos) {
      repo.commit_sha = "";
    }
  }

  async _fetchAndMergeRequirements(url, branch) {
    try {
      const data = await rpc("/cloud/get_repo_requirements", {url, branch});
      if (!data.ok || !data.found || !data.content) return;
      const result = mergeRequirements(this.state.pipDeps, data.content, url, branch);
      this.state.pipDeps = result.content;
      if (result.conflicts.length) {
        this.openPipConflictModal(result.conflicts);
      }
    } catch (e) {
      console.warn("Failed to fetch repo requirements:", e);
    }
  }

  goBack() {
    this.env.navigate("project_detail", {project_id: this.props.project_id});
  }

  envLabel(env) {
    return {staging: _t("Staging"), production: _t("Production")}[env] || env;
  }

  // ── Code editor helpers ────────────────────────────────────────────────

  getLineNumbers(field) {
    const text =
      field === "pipDeps"
        ? this.state.pipDeps
        : field === "aptDeps"
        ? this.state.aptDeps
        : this.state.form[field] || "";
    const lines = Math.max(1, text.split("\n").length);
    return Array.from({length: lines}, (_, i) => i + 1);
  }

  onCodeScroll(ev) {
    const gutter = ev.target.previousElementSibling;
    if (gutter && gutter.classList.contains("ic-code-gutter")) {
      gutter.scrollTop = ev.target.scrollTop;
    }
  }

  // ── Instance actions ──────────────────────────────────────────────────

  get statusLabel() {
    const inst = this.state.inst;
    if (!inst) return "";
    if (inst.state === "deploying") return _t("Building...");
    if (inst.state === "deleting") return _t("Removing...");
    if (!inst.deployed) return _t("Not deployed");
    if (inst.running) return _t("Running");
    if (inst.status === "error") return _t("Error");
    // Checked after "error" on purpose: an instance whose stop is
    // expected can still be broken for an unrelated reason, and
    // "Asleep" would hide it.
    if (inst.stop_is_expected) return _t("Asleep");
    return _t("Stopped");
  }

  get statusClass() {
    const inst = this.state.inst;
    if (!inst) return "";
    // Both in-flight lifecycle states reuse the "building" look; the
    // CSS class names predate the state machine and are left alone.
    if (inst.state === "deploying" || inst.state === "deleting") {
      return "st-provisioning";
    }
    if (!inst.deployed) return "st-pending";
    if (inst.running) return "st-running";
    if (inst.status === "error") return "st-error";
    if (inst.stop_is_expected) return "st-asleep";
    return "st-stopped";
  }

  /**
   * Map one container of this instance to its ``rl-sd`` dot modifier.
   *
   * Reads the state the health probe observed for that service. Falls
   * back to the instance-wide ``running`` flag while nothing has been
   * observed yet — a freshly created instance, or one whose first probe
   * has not landed — which is what every dot showed before, so the card
   * degrades to its old behaviour instead of to a wrong one.
   *
   * Only ``odoo`` can be legitimately stopped: a plan that sleeps an
   * instance stops that container and leaves the rest of the stack up.
   *
   * @param {string} svc compose service name, e.g. "odoo" or "db"
   * @returns {string} "up", "asleep" or "down"
   */
  serviceDotClass(svc) {
    const inst = this.state.inst;
    if (!inst) return "down";
    const observed = (inst.service_states || {})[svc];
    if (observed === undefined) return inst.running ? "up" : "down";
    if (observed === "running") return "up";
    if (svc === "odoo" && inst.stop_is_expected) return "asleep";
    return "down";
  }

  // ── Unified job launcher ──────────────────────────────────────────

  /**
   * Central method to enqueue a job and immediately refresh the UI.
   *
   * @param {Function} fn  - async function that enqueues the job and
   *                          returns {ok, job_id, blocked?, error?} or
   *                          a plain job_id (from orm.call).
   * @param {Object} [opts]
   * @param {boolean} [opts.openLog=false]      - open /cloud/log/<id> on success
   * @param {boolean} [opts.goToOverview=false] - jump to the Overview tab on success
   * @param {string}  [opts.errorLabel]         - fallback toast message
   * @returns {Object|null} the response data, or null on error
   */
  async _enqueueJob(
    fn,
    {
      openLog = false,
      goToOverview = false,
      errorLabel,
      loadingKey = "actionLoading",
    } = {}
  ) {
    if (this.state[loadingKey]) return null;
    this.state[loadingKey] = true;
    try {
      const data = await fn();
      // orm.call returns a plain id; rpc endpoints return {ok, job_id}
      const jobId = typeof data === "number" ? data : data?.job_id;
      if (data?.ok === false || data?.error) {
        this.env.toast?.error(data.error || errorLabel || _t("Action failed"));
        return null;
      }
      if (data?.blocked) {
        this.state.conflictBlocked = {
          alert_id: data.alert_id,
          alert_code: data.alert_code || "",
          message: data.message,
          conflicts: data.conflicts || [],
        };
      } else {
        if (openLog && jobId) {
          window.open(`/cloud/log/${jobId}`, "_blank");
        }
        if (goToOverview) {
          this.setTab("overview");
        }
      }
      // Immediate refresh so the new job shows in Recent Activity
      this._silentRefresh();
      return data;
    } catch (e) {
      this.env.toast?.error(
        e.data?.message || e.message || errorLabel || _t("Action failed")
      );
      return null;
    } finally {
      this.state[loadingKey] = false;
    }
  }

  async deployInstance() {
    await this._enqueueJob(
      () => rpc("/cloud/deploy_instance", {instance_id: this.props.instance_id}),
      {openLog: true, errorLabel: _t("Deploy failed")}
    );
  }

  async rebuildInstance() {
    await this._enqueueJob(
      () => rpc("/cloud/rebuild_instance", {instance_id: this.props.instance_id}),
      {openLog: true, errorLabel: _t("Rebuild failed")}
    );
  }

  /**
   * Run one of the pluggable instance actions.
   *
   * @param {{code: string, name: string, action_confirm?: string}} action
   *   The action as served in ``inst.custom_actions``.
   */
  async instanceAction(action) {
    const inst = this.state.inst;
    if (!inst?.host_id) return;
    // A disruptive action warns before it runs, not after: the job
    // type carries the notice so an extension can add one without
    // touching this component.
    if (action.action_confirm) {
      const confirmed = await this._confirm({
        title: action.name,
        message: action.action_confirm,
        confirmLabel: _t("Run"),
      });
      if (!confirmed) return;
    }
    await this._enqueueJob(() =>
      this.orm.call("cloud.job", "enqueue", [
        inst.host_id,
        this.props.instance_id,
        action.code,
      ])
    );
  }

  viewLogs() {
    window.open(`/cloud/instance/${this.props.instance_id}/logs`, "_blank");
  }

  async exportInstance() {
    const inst = this.state.inst;
    if (!inst?.host_id) return;
    await this._enqueueJob(() =>
      this.orm.call("cloud.job", "enqueue", [
        inst.host_id,
        this.props.instance_id,
        "export_instance",
      ])
    );
  }

  _confirm(opts) {
      return confirmVia(this.state, opts);
  }

  async deleteInstance() {
    const inst = this.state.inst;
    if (inst.deployed) {
      this.state.removeModal = {instance: inst, typed: ""};
      return;
    }
    const confirmed = await this._confirm({
      title: _t("Delete Instance"),
      message: _t(
        'Permanently delete "%s"? It has never been deployed so no SSH cleanup is needed.'
      ).replace("%s", inst.name),
      confirmLabel: _t("Delete"),
      isDanger: true,
    });
    if (!confirmed) return;
    try {
      await rpc("/cloud/delete_instance", {instance_id: this.props.instance_id});
      this._navigateAfterDelete();
    } catch (e) {
      this.env.toast?.error(e.data?.message || e.message || _t("Delete failed"));
    }
  }

  closeRemoveModal() {
    this.state.removeModal = null;
  }

  /**
   * Whether what the operator typed unlocks "Delete completely".
   *
   * Deleting now takes the backups with it, so there is no way back
   * from this button and it asks for the instance name. The name — not
   * a fixed word like DELETE — because the expensive mistake here is
   * almost never "I did not mean to delete": it is "I deleted the wrong
   * one", two similar instances, wrong tab. Typing the name catches
   * that; a fixed word catches nothing.
   *
   * Exact match on purpose: no trimming, no case folding. A barrier
   * that forgives is a barrier you clear on autopilot.
   *
   * @returns {boolean} true when the typed text unlocks the button.
   */
  get removeConfirmed() {
    const modal = this.state.removeModal;
    return !!modal && modal.typed === modal.instance.name;
  }

  /** Remove a deployed instance from the host; keepInPanel decides
   * whether the record survives as a re-deployable draft or is
   * unlinked once the host teardown succeeds. */
  async _removeFromHost(keepInPanel) {
    const inst = this.state.inst;
    this.state.removeModal = null;
    const data = await this._enqueueJob(() =>
      this.orm.call("cloud.job", "enqueue", [
        inst.host_id,
        this.props.instance_id,
        "delete_instance",
        {keep_in_panel: keepInPanel},
      ])
    );
    if (data) this._waitForDeleteJob(data);
  }

  _waitForDeleteJob(jobId) {
    const poll = async () => {
      if (!this._safePoll.alive) return;
      try {
        const [job] = await this.orm.call("cloud.job", "load_jobs", [jobId]);
        if (!this._safePoll.alive) return;
        if (job && ["done", "failed"].includes(job.state)) {
          this._navigateAfterDelete();
          return;
        }
        this._safePoll.schedule(poll, 3000);
      } catch (_) {
        this._safePoll.schedule(poll, 3000);
      }
    };
    this._safePoll.schedule(poll, 2000);
  }

  async _navigateAfterDelete() {
    // Reload so the deleted row is gone from the store before the
    // destination route reads it. The store's bus subscription
    // would catch it eventually, but the user clicks "delete" and
    // navigates immediately — we can't race the debouncer.
    await this.env.projectStore?.load(this.props.project_id);
    const next = this.env.projectStore?.getNextInstance(this.props.instance_id);
    if (next) {
      this.env.navigate("instance_detail", {
        project_id: this.props.project_id,
        instance_id: next.id,
      });
    } else {
      this.env.navigate("project_detail", {project_id: this.props.project_id});
    }
  }
}
