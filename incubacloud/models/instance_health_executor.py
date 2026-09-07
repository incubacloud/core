import re
import shlex
from contextlib import suppress
from datetime import timedelta
from datetime import timezone as tz
from operator import itemgetter

from odoo import fields as odoo_fields

from .abstract_executor import AbstractSSHExecutor

# Alert thresholds
_MEM_WARN_PCT = 85.0      # memory % that triggers a warning once sustained
_CPU_WARN_PCT = 90.0      # CPU %    that triggers a warning once sustained
_ERROR_GROUPS_WARN = 1    # number of distinct ERROR fingerprints since last check
_ERROR_LINES_HEAD = 1500  # cap raw log lines fetched (headers + context)
_ERROR_GROUPS_MAX = 10    # cap distinct fingerprints shipped in the payload
_ERROR_SAMPLE_PER_GRP = 3 # raw lines kept per fingerprint for the payload
_ERROR_CONTEXT_LINES = 60 # log lines captured after each ERROR header

# How long an ``instance_error_logs`` alert must go unseen before a
# clean cycle closes it. See ``_resolve_error_logs_when_quiet``.
_ERROR_QUIET_HOURS = 24

# Shape of the traceback stored per group. An Odoo traceback reaches
# the failing line through ``ir_cron`` → ``ir_actions`` → ``safe_eval``
# → the addon → the ORM: the frames at the top are the same in every
# cron failure, and the exception type and message — the only lines
# that say *what* broke — are the last ones. So trimming always eats
# the middle, and the tail is the last thing to go.
_ERROR_CONTEXT_HEAD = 6           # first lines kept: where it was called from
_ERROR_CONTEXT_TAIL = 14          # last lines kept: the exception itself
_ERROR_CONTEXT_LINE_CHARS = 300   # per-line cap before anything is stored
_ERROR_CONTEXT_MAX_LINES = 200    # accumulation guard for a log in a loop
_ERROR_CONTEXT_SKIPPED = '… %d line(s) skipped …'

# ── Odoo log archive watchdog ─────────────────────────────────────────
# Odoo writes its log to ``logs/odoo.log`` on the host (see
# ``deploy_instance_executor._odoo_command``). The file has two silent
# failure modes, and an instance suffering either looks perfectly
# healthy from every other angle this probe measures.
_LOG_STDOUT_LEAK_LINES = 5          # Odoo lines still on stdout ⇒ fallback
_LOG_MAX_BYTES = 512 * 1024 * 1024  # a live log this big ⇒ nothing rotates it
_LOG_ARCHIVE_TAIL = 5000            # lines read back from the newest archive
_LOG_LIVE_TAIL = 20000              # lines read back from the live file
_LOG_SINCE_GRACE_MIN = 5            # clock-skew margin on the cutoff

#: Odoo's own line prefix: date, time with fractional seconds, pid.
#: Used both to tell the probe's window apart and to spot Odoo output
#: that is still going to the container instead of the file.
_ODOO_LINE_GREP = (
    r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[.,]\d+\s+\d+\s'
)

#: Keep the lines logged at or after ``c``, and the lines that follow
#: them without a timestamp of their own — a traceback belongs to the
#: header above it, so filtering it out by timestamp would throw away
#: exactly the context the alert exists to carry. Intervals are spelled
#: out because mawk (Debian's default awk) is the one reading this.
_AWK_SINCE_PROG = (
    "match($0, /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] "
    "[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) "
    "{ keep = (substr($0, RSTART, RLENGTH) >= c) } keep"
)

#: The live file, and only as a regular file. ``logs/`` belongs to the
#: container's uid and the probe runs on the host as the SSH user, so
#: a symlink put in its place from inside the container must not be
#: followed — by ``tail`` here nor by ``stat`` in the health reading.
_LIVE_LOG_IS_REGULAR = "[ -f logs/odoo.log ] && [ ! -L logs/odoo.log ]"

#: Newest archived day, chosen among regular files with logrotate's
#: shapes only — the same reason: ``ls -1t logs/odoo.log.*`` would
#: happily pick a planted link as "the newest" and ``zcat`` would read
#: whatever host file it points at into the error sample.
_NEWEST_ARCHIVE = (
    "find logs -maxdepth 1 -type f -regextype posix-extended "
    "-regex 'logs/odoo\\.log\\.[0-9]{4}-[0-9]{2}-[0-9]{2}(\\.gz)?' "
    "-printf '%T@ %p\\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-"
)
_ERROR_CONTEXT_CHARS = 4000  # hard cap on the context stored per group

# Hysteresis: how many consecutive cycles must stay above the CPU/memory
# threshold before we surface the alert. With the cron firing every 5 min,
# a value of 2 means "the symptom was there twice in 10 min". Single-cycle
# spikes (deploys we missed gating on, GC pauses, transient bursts) are
# dropped on the floor.
_STREAK_REQUIRED = 2

# Job types that legitimately drive CPU / memory / log noise on the
# instance and would produce false-positive alerts if the health probe
# ran concurrently. When any of these has an *active* cloud.job pointing
# at the same instance, we skip the entire health pass — we still bump
# ``last_health_check`` so the schedule doesn't drift and the SPA shows
# a fresh timestamp.
_BLOCKING_JOB_TYPES = (
    'deploy_instance',
    'rebuild_instance',
    'full_setup',
    'restore_instance',
)

# Odoo log line prefix: "2026-05-17 18:30:21,415 1 ERROR devel module.path: "
# We strip the timestamp+pid+db so identical errors at different times
# collapse into one fingerprint.
_LOG_PREFIX_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}[.,]\d+\s+\d+\s+'
)
# Generic digit runs (record ids, durations, addresses) get masked
# so "Record 42 not found" and "Record 9123 not found" share a fingerprint.
# Greedy on any 1+ digit run — for log dedupe purposes single-digit
# codes are just as much noise as longer ones.
_DIGIT_RUN_RE = re.compile(r'\b\d+\b')
# Hex / pointer-like runs (object ids, memory addrs) — same treatment.
_HEX_RUN_RE = re.compile(r'\b0x[0-9a-fA-F]+\b')
_FINGERPRINT_MAX_LEN = 160
# Same anchor as the remote grep, applied on our side to tell an ERROR
# header from the traceback lines ``grep -A`` prints after it. Those
# carry no level field, which is exactly why the anchored grep used to
# drop them — and why an alert could never be diagnosed once the
# container had been recreated.
_ERROR_HEADER_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[.,]\d+\s+\d+\s+'
    r'(ERROR|CRITICAL)\s'
)
# Any Odoo log record, at any level. ``grep -A`` keeps printing for a
# fixed number of lines after each ERROR header, so once the traceback
# is over what arrives is simply the next record — INFO more often than
# not. That is not context: filing it under the header spent the tail
# budget that exists to keep the exception itself.
_LOG_LINE_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[.,]\d+\s+\d+\s+'
    r'(DEBUG|INFO|WARNING|ERROR|CRITICAL)\s'
)


class InstanceHealthExecutor(AbstractSSHExecutor):
    """Checks the health of a deployed doodba instance.

    Checks performed:
    1. Container state — is the ``odoo`` container running?
    2. HTTP health — does Odoo respond on port 8069? (exec inside container)
    3. CPU / memory snapshot — one ``docker stats --no-stream`` reading.
       Combined with a per-instance streak counter, an alert is only
       raised after ``_STREAK_REQUIRED`` consecutive cycles above the
       threshold — single-cycle spikes are intentionally ignored.
    4. Error logs — fetch up to ``_ERROR_LINES_HEAD`` ERROR lines since
       the last check and dedupe them into fingerprint groups. The
       alert payload carries the groups so the operator does not need
       to SSH into the host to see *which* errors fired.

    Skipped entirely when an intrusive job (deploy / rebuild / restore /
    full setup) is in flight on the same instance: those jobs are the
    only ones that legitimately drive resource usage and log noise
    above the thresholds, so probing during them is pure noise.

    State writes on ``cloud.instance``:
    - Container down  → ``running=False``, ``status='error'``
    - Up + issues     → ``running=True``,  ``status='warning'`` or ``'error'``
    - All clear       → ``running=True``,  ``status='ok'``

    Instance-scoped alert codes: ``instance_down``, ``instance_unresponsive``,
    ``instance_high_cpu``, ``instance_high_memory``, ``instance_error_logs``.
    """

    _job_type = "instance_health"

    # Retry transient connection failures (host briefly unreachable) rather
    # than failing on the first blip; only alert if the host is still
    # unreachable after the last attempt. See AbstractExecutor.
    _retry_on_connection_loss = True

    # Class attribute so layered modules can extend the blocking set
    # with their own intrusive job types (e.g. the SaaS tenant/warm
    # deploy and rebuild flows) without touching this module.
    _blocking_job_types = _BLOCKING_JOB_TYPES

    # ── Helpers ────────────────────────────────────────────────────────────

    def _inst(self):
        return self.job.instance_id

    def _is_blocked_by_active_job(self):
        """True iff another active job on the same instance would make
        the resource snapshot meaningless (deploy/rebuild/etc.).
        """
        inst = self._inst()
        if not inst:
            return False
        Job = self.env['cloud.job']
        return bool(Job.search_count([
            ('id', '!=', self.job.id),
            ('instance_id', '=', inst.id),
            ('state', 'in', Job._active_states),
            ('job_type_id.code', 'in', list(self._blocking_job_types)),
        ]))

    def _odoo_stop_is_expected(self):
        """Whether a stopped-but-present ``odoo`` container is normal.

        Core has no concept of scheduled sleep, so this is always
        False and a stopped ``odoo`` keeps raising ``instance_down``.
        Layered modules override it (the SaaS manager returns True for
        sleep-eligible tenants, whose ``odoo`` is stopped by Sablier on
        inactivity). Only consulted when the container *exists*: a
        missing container is never expected and always alerts.
        """
        return False

    # ── AbstractSSHExecutor interface ─────────────────────────────────────

    async def before_execute(self, transport):
        inst = self._inst()
        self._sys(f"Checking health of '{inst.name}'…")
        self._skipped = self._is_blocked_by_active_job()
        if self._skipped:
            self._sys(
                "Skipped — an intrusive job (deploy / rebuild / restore) "
                "is currently running on this instance. "
                "Resource and log readings would be meaningless."
            )

    def _error_lines_command(self, d, since, cutoff):
        """Return the command that samples ERROR lines for this cycle.

        Reads the log file on the host — the copy that survives a
        rebuild, which is what makes the sample still explain an error
        an hour after the container that raised it was replaced — and
        falls back to the container's output for an instance that has
        not been rebuilt since file logging shipped.

        The newest archive is read alongside the live file because
        rotation happens at midnight and this window straddles it once
        a day; both are bounded so a runaway log cannot blow up the
        parse. Only regular files are read: ``logs/`` is writable from
        inside the container, and a symlink planted there would
        otherwise be followed on the host by this very command.

        :param str d: remote instance directory
        :param str since: ``docker compose logs --since`` value (fallback)
        :param str cutoff: ``YYYY-MM-DD HH:MM:SS`` lower bound for the file
        :return: the shell command
        """
        awk_since = (
            f'awk -v c={shlex.quote(cutoff)} {shlex.quote(_AWK_SINCE_PROG)}'
        )
        grep = (
            "grep -aP "
            "'" + _ODOO_LINE_GREP.replace("^", "\\b").replace("\\s$", "")
            + "(\\x1b\\[[0-9;]+m)*(ERROR|CRITICAL)(\\x1b\\[[0-9;]+m)*\\s' "
            f"-A {_ERROR_CONTEXT_LINES}"
        )
        return (
            f"cd {d} && "
            f"{{ if {_LIVE_LOG_IS_REGULAR}; then "
            f"{{ {_NEWEST_ARCHIVE} "
            f"| xargs -r zcat -f 2>/dev/null | tail -n {_LOG_ARCHIVE_TAIL}; "
            f"tail -n {_LOG_LIVE_TAIL} logs/odoo.log 2>/dev/null; }} "
            f"| {awk_since}; "
            f"else docker compose logs --no-color "
            f"--since '{since}' odoo 2>&1; "
            f"fi; }} "
            f"| {grep} "
            f"| sed -E 's/\\x1b\\[[0-9;]*m//g' "
            f"| head -{_ERROR_LINES_HEAD} || true"
        )

    def _log_health_command(self, d):
        """Return the command that reports the state of the log archive.

        Three readings in one round trip: whether the instance has the
        log mount at all, how big the live file is, and how many Odoo
        lines still reach the container's output — which is where Odoo
        goes when it cannot write to the file.

        :param str d: remote instance directory
        :return: the shell command
        """
        return (
            f"cd {d} && "
            f"if [ -d logs ]; then "
            f"printf 'dir:1\\n'; "
            f"printf 'size:%s\\n' "
            f"\"$({{ {_LIVE_LOG_IS_REGULAR} && stat -c %s logs/odoo.log; }} "
            f"2>/dev/null || echo 0)\"; "
            f"printf 'stdout:%s\\n' "
            f"\"$(docker compose logs --no-color --since 30m --tail 500 odoo "
            f"2>/dev/null | grep -acP '{_ODOO_LINE_GREP}' || true)\"; "
            f"else printf 'dir:0\\n'; fi"
        )

    def get_commands(self):
        # If we are skipping this cycle, run a single cheap no-op so the
        # executor still produces results to traverse. Keeping the shape
        # of ``get_commands`` non-empty avoids special-casing the
        # AbstractSSHExecutor loop.
        if getattr(self, '_skipped', False):
            return [("noop", "true")]

        inst = self._inst()
        d = self._inst_dir(inst)

        lhc = inst.last_health_check
        if lhc:
            since = lhc.replace(tzinfo=tz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            window_start = lhc
        else:
            since = "10m"
            window_start = odoo_fields.Datetime.now() - timedelta(minutes=10)
        # The file has no ``--since``: its lines are filtered by the
        # timestamp Odoo wrote, which is the container's clock. A few
        # minutes of grace absorb the skew between it and ours; the
        # cost of overlapping is a repeated alert (they are upserted by
        # code), the cost of undershooting would be a missed error.
        cutoff = (
            window_start - timedelta(minutes=_LOG_SINCE_GRACE_MIN)
        ).strftime('%Y-%m-%d %H:%M:%S')

        return [
            # 1. Container state. ``-a`` includes stopped containers so
            #    a present-but-exited service (a Sablier-slept tenant)
            #    can be told apart from a *missing* one (pruned or never
            #    created) — the two demand opposite reactions.
            (
                "container_state",
                f"cd {d} && "
                f"docker compose ps -a --format '{{{{.Service}}}}\t{{{{.State}}}}' 2>&1",
            ),
            # 2. CPU / memory — single non-streaming snapshot (~1.5 s).
            # `docker stats --no-stream` already computes CPU% from two
            # internal samples taken ~1 s apart, so we get an instantaneous
            # but real CPU reading without the cost (and false positives)
            # of holding the SSH channel open for 20 s.
            (
                "cpu_mem_snapshot",
                f"CTNR=$(cd {d} && docker compose ps -q odoo 2>/dev/null | head -1) && "
                f"[ -n \"$CTNR\" ] && "
                f"docker stats --no-stream "
                f"--format '{{{{.CPUPerc}}}}\t{{{{.MemPerc}}}}' \"$CTNR\" 2>/dev/null | "
                f"sed 's/%//g' | "
                f"awk -F'\\t' "
                f"'{{gsub(/[^0-9.]/,\"\",$1);gsub(/[^0-9.]/,\"\",$2);"
                f"printf \"%.1f\\t%.1f\\n\",$1+0,$2+0}}' "
                f"|| echo '0.0\t0.0'",
            ),
            # 3. HTTP health — curl inside the odoo container
            (
                "http_health",
                f"cd {d} && "
                f"docker compose exec -T odoo "
                f"curl -sf --max-time 15 http://localhost:8069/web/health "
                f"> /dev/null 2>&1; echo \"exit:$?\"",
            ),
            # 4. ERROR lines in odoo logs since last check — raw sample,
            # capped to _ERROR_LINES_HEAD so a runaway log loop can't
            # blow up parsing memory. Dedupe happens in parse_results.
            # ``-A`` carries the traceback that follows each header:
            # those lines have no level field of their own, so without
            # it the payload kept the headline and nothing to diagnose
            # it with once the container had been recreated.
            # The grep is anchored to the Odoo log-level field (after the
            # "<date> <time> <pid>" prefix) so substrings of the word ERROR
            # inside INFO/DEBUG lines — notably asyncssh logging the very
            # command we run here — do not generate self-referential
            # false positives. The trailing sed strips ANSI color codes
            # that Odoo injects around the level keyword so samples stored
            # in the alert payload render as plain text.
            (
                "error_lines",
                self._error_lines_command(d, since, cutoff),
            ),
            # 5. State of the archive itself. Its two failure modes are
            #    invisible to every other reading above: Odoo falling
            #    back to the container's output (the mount is not
            #    writable) and a log nothing ever rotates.
            (
                "log_health",
                self._log_health_command(d),
            ),
        ]

    def parse_results(self, results):
        # Skipped pass: nothing to parse, on_success just stamps the timestamp.
        if getattr(self, '_skipped', False):
            return []

        # 1. Container state — collect *every* service so the per-service
        #    alerts below can compare against ``expected_services()``.
        #    ``self._container_running`` keeps its narrower meaning
        #    (specifically: is ``odoo`` up?) because it gates the HTTP
        #    health check and the ``instance_down`` alert downstream.
        state_out = results.get("container_state", {}).get("stdout", "")
        self._service_states = {}
        for line in state_out.splitlines():
            parts = line.strip().split('\t')
            if len(parts) >= 2:
                svc = parts[0].strip()
                if not svc:
                    continue
                state = parts[1].strip().lower()
                # ``ps -a`` may list several containers for one service
                # (stale one-off ``run`` leftovers next to the real
                # one). A running container always wins: the service is
                # up no matter how many corpses sit beside it.
                if self._service_states.get(svc) != 'running':
                    self._service_states[svc] = state
        self._container_running = (
            self._service_states.get('odoo') == 'running'
        )

        # 2. CPU / memory snapshot
        cm_out = results.get("cpu_mem_snapshot", {}).get("stdout", "0.0\t0.0").strip()
        self._cpu_current = 0.0
        self._mem_current = 0.0
        parts = cm_out.split('\t')
        if len(parts) >= 2:
            with suppress(ValueError):
                self._cpu_current = float(parts[0].strip())
                self._mem_current = float(parts[1].strip())

        # 3. HTTP health
        http_out = results.get("http_health", {}).get("stdout", "").strip()
        self._http_ok = "exit:0" in http_out

        # 4. ERROR lines → fingerprint groups
        err_out = results.get("error_lines", {}).get("stdout", "")
        self._error_groups = self._dedupe_error_lines(err_out)
        self._error_total = sum(g['count'] for g in self._error_groups)

        # 5. Log archive state. Absent for a probe that predates the
        #    reading (one already in flight during an upgrade), which
        #    must grade nothing rather than guess.
        self._log_health = self._parse_log_health(
            results.get("log_health", {}).get("stdout", ""),
        )

        return []  # never hard-fail the job — report via status/alerts

    # ── Log archive health ────────────────────────────────────────────────

    def _parse_log_health(self, raw):
        """Turn the ``log_health`` reading into a dict, or None.

        :param str raw: ``dir:…/size:…/stdout:…`` lines from the host
        :return: ``{'dir': bool, 'size': int, 'stdout': int}`` or None
            when the command did not run (nothing to grade).
        """
        if not raw or 'dir:' not in raw:
            return None
        health = {'dir': False, 'size': 0, 'stdout': 0}
        for line in raw.splitlines():
            key, _sep, value = line.strip().partition(':')
            if key not in health:
                continue
            with suppress(ValueError):
                number = int(value.strip() or 0)
                health[key] = bool(number) if key == 'dir' else number
        return health

    def _grade_log_health(self, inst):
        """Alert on the two silent failures of the log archive.

        *fallback* — the mount is there but Odoo's output is still
        coming out of the container, so nothing is being archived and
        the next rebuild will take the history with it. *rotation
        stalled* — the live file grew past any sane daily size, so
        logrotate is not running and the disk is filling up: the very
        thing the archive was supposed to bound.
        """
        health = getattr(self, '_log_health', None)
        if not health or not health['dir']:
            # Nothing to grade: an instance not rebuilt since file
            # logging shipped keeps its capped container output.
            self._resolve_inst_alert('instance_logs_unhealthy')
            return
        if health['stdout'] >= _LOG_STDOUT_LEAK_LINES:
            self._inst_alert(
                'instance_logs_unhealthy',
                (
                    f"Odoo on '{inst.name}' is logging to the container "
                    f"instead of logs/odoo.log, so nothing is archived and "
                    f"its next rebuild will discard the history. Check that "
                    f"logs/ exists and belongs to uid 1000."
                ),
                level='warning',
                payload={
                    'reason': 'fallback',
                    'stdout_lines': health['stdout'],
                },
            )
            self._sys(
                "⚠ Odoo is logging to the container, not to logs/odoo.log."
            )
        elif health['size'] > _LOG_MAX_BYTES:
            self._inst_alert(
                'instance_logs_unhealthy',
                (
                    f"logs/odoo.log on '{inst.name}' is "
                    f"{health['size'] // (1024 * 1024)} MB: nothing is "
                    f"rotating it. Check logrotate on the host "
                    f"(/etc/logrotate.d/incubacloud-*)."
                ),
                level='warning',
                payload={
                    'reason': 'rotation_stalled',
                    'size': health['size'],
                },
            )
            self._sys("⚠ logs/odoo.log is not being rotated.")
        else:
            self._resolve_inst_alert('instance_logs_unhealthy')

    # ── Error log dedupe ──────────────────────────────────────────────────

    def _fingerprint(self, line):
        """Collapse an Odoo log line into a fingerprint that ignores
        timestamps, PIDs, numeric ids and pointer-like runs so that
        identical errors with different metadata group together.
        """
        stripped = _LOG_PREFIX_RE.sub('', line.strip())
        stripped = _HEX_RUN_RE.sub('<HEX>', stripped)
        stripped = _DIGIT_RUN_RE.sub('<N>', stripped)
        return stripped[:_FINGERPRINT_MAX_LEN]

    def _append_context(self, group, line):
        """Store one traceback line under its ERROR group.

        Only the first occurrence of a fingerprint contributes context —
        every repeat carries the same stack. Lines are kept as they come
        and the group is compacted once it closes; the guard here is
        only against a log stuck in a loop, and even that drops from the
        middle, because the end of a traceback is the part worth having.
        """
        if group['count'] > 1:
            return
        group['context'].append(line[:_ERROR_CONTEXT_LINE_CHARS])
        if len(group['context']) > _ERROR_CONTEXT_MAX_LINES:
            del group['context'][_ERROR_CONTEXT_HEAD]
            group['skipped'] += 1

    def _compact_context(self, group):
        """Reduce a group's context to head + marker + tail, in place.

        Called once the whole blob is parsed, so the tail is known. The
        alert that hid a fleet-wide cron failure for a week stored the
        first twenty-five lines of its traceback and stopped one frame
        short of ``AccessError: … "core_saas_url"`` — every line it did
        keep was boilerplate shared by every cron failure there is.

        Both budgets (lines and characters) are spent from the middle
        outwards: the head goes first, then the oldest tail lines, and
        the very last line survives everything.
        """
        skipped = group.pop('skipped', 0)
        head = group['context'][:_ERROR_CONTEXT_HEAD]
        tail = group['context'][_ERROR_CONTEXT_HEAD:]
        if len(tail) > _ERROR_CONTEXT_TAIL:
            skipped += len(tail) - _ERROR_CONTEXT_TAIL
            tail = tail[-_ERROR_CONTEXT_TAIL:]

        def _stored_size():
            marker = len(_ERROR_CONTEXT_SKIPPED % skipped) if skipped else 0
            return (
                sum(len(line) for line in head)
                + sum(len(line) for line in tail)
                + marker
            )

        while _stored_size() > _ERROR_CONTEXT_CHARS and head:
            head.pop()
            skipped += 1
        while _stored_size() > _ERROR_CONTEXT_CHARS and len(tail) > 1:
            tail.pop(0)
            skipped += 1
        group['context'] = head + (
            [_ERROR_CONTEXT_SKIPPED % skipped] if skipped else []
        ) + tail

    def _dedupe_error_lines(self, raw):
        """Turn a blob of raw log lines into an ordered list of groups:
        ``[{'fingerprint', 'count', 'samples', 'context'}, ...]``, sorted
        by count descending, capped to ``_ERROR_GROUPS_MAX``.

        The blob interleaves ERROR headers with the traceback lines
        ``grep -A`` printed after each one, so headers are recognised by
        ``_ERROR_HEADER_RE`` and anything else is filed as context of the
        header above it. ``count`` therefore still counts ERROR lines,
        not log lines. Blocks are separated by grep's own ``--`` marker,
        which closes the context of whatever preceded it — and so does
        the next log record of any level (``_LOG_LINE_RE``): ``grep -A``
        counts lines, not frames, so what follows a traceback is what
        happened next, not what explains it.
        """
        groups = {}
        order = []
        current = None
        for line in raw.splitlines():
            line = line.rstrip()
            if not line or line == '--':
                current = None
                continue
            if not _ERROR_HEADER_RE.match(line):
                if _LOG_LINE_RE.match(line):
                    # The next record: the traceback above ended here.
                    current = None
                elif current is not None:
                    self._append_context(current, line)
                continue
            fp = self._fingerprint(line)
            if not fp:
                current = None
                continue
            if fp not in groups:
                groups[fp] = {
                    'fingerprint': fp,
                    'count': 0,
                    'samples': [],
                    'context': [],
                    'skipped': 0,
                }
                order.append(fp)
            grp = groups[fp]
            grp['count'] += 1
            if len(grp['samples']) < _ERROR_SAMPLE_PER_GRP:
                grp['samples'].append(line[:512])
            current = grp
        ordered = sorted(
            (groups[fp] for fp in order),
            key=itemgetter('count'),
            reverse=True,
        )
        shipped = ordered[:_ERROR_GROUPS_MAX]
        for group in shipped:
            self._compact_context(group)
        return shipped

    # ── Outcome ───────────────────────────────────────────────────────────

    async def on_success(self, results):
        inst = self._inst()

        # We just ran commands over SSH, so the host is reachable: clear any
        # stale host-unreachable alert left by a previous outage.
        self._resolve_alert('host_unreachable')

        # Always stamp the timestamp so the schedule visibly advances
        # even when the cycle is a no-op (skipped).
        inst.write({'last_health_check': odoo_fields.Datetime.now()})

        if getattr(self, '_skipped', False):
            # Reset streaks too: a fresh deploy/rebuild typically wipes
            # the previous baseline, so resuming from streak=1 next
            # cycle would be misleading.
            inst.write({
                'cpu_over_threshold_streak': 0,
                'mem_over_threshold_streak': 0,
                'http_fail_streak': 0,
            })
            self._resolve_inst_alert('instance_unresponsive')
            return

        # The log archive is about files on the host, not about the
        # container: grade it before any branch that returns early, so
        # a sleeping or stopped instance is graded too.
        self._grade_log_health(inst)

        # Keep what the container listing said, rather than only
        # alerting on it and dropping it. Every branch below returns at
        # some point, so this is stamped before any of them: the panel
        # paints one dot per service from it, and a stopped ``db`` next
        # to a running ``odoo`` used to be invisible there — both dots
        # came from the single ``running`` flag.
        inst.write({'service_states': self._service_states})

        # Who owns ``running``. Both this probe and the metrics cron can
        # tell whether an instance is up, and with observability on they
        # would otherwise both write the flag on their own schedules —
        # agreeing most of the time and flapping whenever they briefly
        # did not. Metrics win while their readings are fresh; this probe
        # keeps doing everything else (HTTP, log scraping) and takes the
        # flag back by itself the moment they go stale.
        owns_running = not inst._liveness_covered_by_metrics()

        if not self._container_running:
            odoo_present = 'odoo' in self._service_states
            if odoo_present and self._odoo_stop_is_expected():
                # Present but stopped, and the stop is scheduled (e.g.
                # Sablier sleep): not an incident. ``running=False`` is
                # still written — downstream hooks read it to track the
                # sleep/wake cycle — but status stays green and no
                # alert fires. The companion services must keep
                # running while the instance sleeps, so they are still
                # graded below.
                vals = {
                    'cpu_over_threshold_streak': 0,
                    'mem_over_threshold_streak': 0,
                    'http_fail_streak': 0,
                }
                if owns_running:
                    vals['running'] = False
                inst.write(vals)
                self._resolve_inst_alert('instance_down')
                # A stopped container cannot be "not answering on 8069":
                # the HTTP track only means anything while odoo is up.
                # Without this the probe that caught a tenant mid-wake
                # left a *critical* alert standing for as long as the
                # tenant then slept — measured at ten hours on a Free
                # tenant that was behaving exactly as designed.
                self._resolve_inst_alert('instance_unresponsive')
                issues = []
                self._check_other_services(inst, issues)
                inst.write({'status': 'warning' if issues else 'ok'})
                self._sys(f"✓ '{inst.name}' is asleep (expected).")
                return
            vals = {
                'status': 'error',
                'cpu_over_threshold_streak': 0,
                'mem_over_threshold_streak': 0,
                'http_fail_streak': 0,
            }
            if owns_running:
                vals['running'] = False
            inst.write(vals)
            # ``instance_down`` is the incident here, and it is already
            # critical. Leaving ``instance_unresponsive`` standing too
            # would report one outage twice, with the weaker of the two
            # descriptions surviving the longest.
            self._resolve_inst_alert('instance_unresponsive')
            if odoo_present:
                message = f"Container 'odoo' is not running on '{inst.name}'."
                log = f"✗ Container down — '{inst.name}' is not running."
            else:
                # No container at all — not even a stopped one. This is
                # how a pruned stack presents itself; say so instead of
                # the generic "not running" that once cost a log dig.
                message = (
                    f"Container 'odoo' is missing on '{inst.name}' "
                    f"(pruned, or never created)."
                )
                log = f"✗ Container missing — '{inst.name}' has no odoo container."
            self._inst_alert('instance_down', message, level='critical')
            self._sys(log)
            return

        # Container is up — resolve down alert if it existed
        self._resolve_inst_alert('instance_down')
        if owns_running:
            inst.write({'running': True})

        issues = []

        # HTTP health — with hysteresis, exactly like CPU and memory
        # below. A container that is up but not yet listening is what
        # every single boot looks like from out here (curl exits 7 or
        # 56), and Free tenants boot several times a day: Sablier wakes
        # them, and a core release rebuilds them. Alerting on the first
        # failed probe made "Odoo is starting" indistinguishable from
        # "Odoo is down", at critical severity.
        if not self._http_ok:
            new_http_streak = inst.http_fail_streak + 1
            inst.write({'http_fail_streak': new_http_streak})
            issues.append('unresponsive')
            if new_http_streak >= _STREAK_REQUIRED:
                self._inst_alert(
                    'instance_unresponsive',
                    f"Odoo HTTP health check failed on '{inst.name}' "
                    f"for {new_http_streak} consecutive checks "
                    f"(port 8069 not responding).",
                    level='critical',
                )
            self._sys(
                f"✗ HTTP health check failed — Odoo not responding "
                f"(streak {new_http_streak}/{_STREAK_REQUIRED})."
            )
        else:
            inst.write({'http_fail_streak': 0})
            self._resolve_inst_alert('instance_unresponsive')

        # Memory — with hysteresis
        mem_over = self._mem_current >= _MEM_WARN_PCT
        new_mem_streak = (inst.mem_over_threshold_streak + 1) if mem_over else 0
        inst.write({'mem_over_threshold_streak': new_mem_streak})
        if mem_over and new_mem_streak >= _STREAK_REQUIRED:
            issues.append(f'mem:{self._mem_current:.0f}%')
            self._inst_alert(
                'instance_high_memory',
                f"Memory at {self._mem_current:.0f}% on '{inst.name}' "
                f"for {new_mem_streak} consecutive checks "
                f"(threshold {_MEM_WARN_PCT:.0f}%).",
                level='warning',
            )
            self._sys(
                f"⚠ Memory: {self._mem_current:.0f}% "
                f"(streak {new_mem_streak}/{_STREAK_REQUIRED})"
            )
        elif not mem_over:
            self._resolve_inst_alert('instance_high_memory')

        # CPU — with hysteresis
        cpu_over = self._cpu_current >= _CPU_WARN_PCT
        new_cpu_streak = (inst.cpu_over_threshold_streak + 1) if cpu_over else 0
        inst.write({'cpu_over_threshold_streak': new_cpu_streak})
        if cpu_over and new_cpu_streak >= _STREAK_REQUIRED:
            issues.append(f'cpu:{self._cpu_current:.0f}%')
            self._inst_alert(
                'instance_high_cpu',
                f"CPU at {self._cpu_current:.0f}% on '{inst.name}' "
                f"for {new_cpu_streak} consecutive checks "
                f"(threshold {_CPU_WARN_PCT:.0f}%).",
                level='warning',
            )
            self._sys(
                f"⚠ CPU: {self._cpu_current:.0f}% "
                f"(streak {new_cpu_streak}/{_STREAK_REQUIRED})"
            )
        elif not cpu_over:
            self._resolve_inst_alert('instance_high_cpu')

        self._check_other_services(inst, issues)

        # Error logs — dedupe groups + payload
        if len(self._error_groups) >= _ERROR_GROUPS_WARN:
            issues.append(f'errors:{self._error_total}')
            top = self._error_groups[0]
            top_sample = (top['samples'][0] if top['samples'] else top['fingerprint'])
            self._inst_alert(
                'instance_error_logs',
                (
                    f"{self._error_total} ERROR line(s) in "
                    f"{len(self._error_groups)} group(s) on '{inst.name}'. "
                    f"Top: {top_sample[:200]}"
                ),
                level='warning',
                payload=self._error_groups,
            )
            self._sys(
                f"⚠ {self._error_total} ERROR lines in logs "
                f"({len(self._error_groups)} unique group(s))."
            )
        else:
            self._resolve_error_logs_when_quiet()

        # Derive overall status
        if 'unresponsive' in issues:
            inst.write({'status': 'error'})
        elif issues:
            inst.write({'status': 'warning'})
        else:
            inst.write({'status': 'ok'})
            self._sys(
                f"✓ '{inst.name}' healthy — "
                f"CPU {self._cpu_current:.0f}% · Mem {self._mem_current:.0f}%"
            )

    def _check_other_services(self, inst, issues):
        """Grade every expected non-``odoo`` service; append to *issues*.

        Alerts on any expected service that is not ``running``.
        ``odoo`` is intentionally excluded because it has its own
        end-to-end track (``instance_down`` for the container,
        ``instance_unresponsive`` for HTTP) which carries the right
        severity (``critical``). Backup, db, smtp going sideways is a
        ``warning`` — the instance keeps serving traffic — but stays
        visible so the operator does not learn about a 2-day-old broken
        backup container from a failed cron. Also runs while the
        instance sleeps: Sablier only stops ``odoo``, so its companions
        must stay up.
        """
        expected_other = set(inst.expected_services()) - {'odoo'}
        all_known = expected_other | {
            svc for svc in self._service_states
            if svc != 'odoo'
        }
        for svc in sorted(all_known):
            code = f'instance_service_{svc}_down'
            if svc not in expected_other:
                # Service runs on the host but the instance doesn't
                # actually need it (e.g. backup container left over
                # from a plan downgrade). Drop any stale alert and
                # move on — we don't grade what we don't expect.
                self._resolve_inst_alert(code)
                continue
            observed = self._service_states.get(svc)
            if observed != 'running':
                issues.append(f'{svc}:{observed or "missing"}')
                self._inst_alert(
                    code,
                    (
                        f"Container '{svc}' is {observed or 'missing'} "
                        f"on '{inst.name}'."
                    ),
                    level='warning',
                    payload={'service': svc, 'state': observed or 'missing'},
                )
                self._sys(
                    f"⚠ Service '{svc}' is {observed or 'missing'}."
                )
            else:
                self._resolve_inst_alert(code)

    # ── Instance-scoped alert helpers ─────────────────────────────────────

    def _inst_alert(self, code, message, level='warning', payload=None):
        """Raise (or refresh) the instance-scoped alert for *code*.

        Delegates to ``cloud.alert.raise_alert`` rather than repeating
        the dedup rule: this used to be a second search-then-create,
        which is exactly how two copies of one recipe drift apart — and
        this copy was the one missing the unique-index savepoint. The
        private cursor stays, for the same reason ``_alert`` has one:
        an alert about a failure must survive the rollback of the
        transaction that failed.
        """
        inst = self._inst()
        with self.job.env.registry.cursor() as cr:
            env = self.job.env(cr=cr)
            env['cloud.alert'].raise_alert(
                code, message, level=level,
                instance=env['cloud.instance'].browse(inst.id),
                job=env['cloud.job'].browse(self.job.id),
                payload=payload,
            )

    def _resolve_error_logs_when_quiet(self):
        """Dismiss ``instance_error_logs`` only after a full quiet day.

        Every other alert this probe raises describes a condition it can
        read right now, so a clean cycle is genuinely the end of it.
        This one describes something that already happened, and the
        window is only the few minutes since the last check: an error
        that fires every six hours raised an alert that the very next
        cycle dismissed, notifying on-call twice about something nobody
        could act on in between, and leaving the panel — which filters
        to active by default — showing nothing at all. That is how a
        cron stayed broken across the whole tenant fleet for a week.

        ``create_date`` is the fallback for rows written before
        ``last_raised_at`` existed; without it every alert open at
        deploy time would stay open for ever.
        """
        inst = self._inst()
        cutoff = odoo_fields.Datetime.now() - timedelta(
            hours=_ERROR_QUIET_HOURS,
        )
        with self.job.env.registry.cursor() as cr:
            env = self.job.env(cr=cr)
            instance = env['cloud.instance'].browse(inst.id)
            Alert = env['cloud.alert']
            alert = Alert.search(
                Alert._dedup_domain(
                    'instance_error_logs', instance=instance,
                ),
                limit=1,
            )
            if not alert:
                return
            last_seen = alert.last_raised_at or alert.create_date
            if last_seen and last_seen > cutoff:
                return
            Alert.resolve_alert('instance_error_logs', instance=instance)

    def _resolve_inst_alert(self, code):
        """Dismiss the active instance-scoped alert for *code*.

        Goes through ``resolve_alert`` so the closure reaches the
        on-call channels too: a hand-rolled ``write`` dismissed the row
        silently, leaving every incident that had toasted Telegram
        looking permanently open there.
        """
        inst = self._inst()
        with self.job.env.registry.cursor() as cr:
            env = self.job.env(cr=cr)
            env['cloud.alert'].resolve_alert(
                code, instance=env['cloud.instance'].browse(inst.id),
            )
