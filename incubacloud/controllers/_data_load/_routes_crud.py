"""CRUD endpoints for projects, hosts, instances, tags, users, secrets,
dashboard, alerts, sync and general settings.

Mixed into ``CloudDataLoadController`` in ``data_load.py``. Each method
relies on ``self._sec()`` (defined on the controller) for permission
checks.
"""
import logging

import asyncssh

from odoo import _, fields, http
from odoo.exceptions import AccessError, UserError, ValidationError
from odoo.http import request

from ...github.client import GitHubAppClient, GitHubAPIError, GitHubPATClient
from ...models._repo_requirements import (
    CONFLICT_RE,
    _parse_req_line,
    _repo_alias,
    apply_sync,
    compare_instance_project,
    create_pip_conflict_alert,
    detect_pip_conflicts,
    fetch_requirements_txt,
    merge_pip_requirements,
    repo_key_for_source_label,
)
from ...models.cloud_settings import (
    CONTAINER_LOG_MAX_FILE_DEFAULT,
    LOG_DOWNLOAD_MAX_MB_DEFAULT,
    LOG_SEARCH_MAX_FILES_DEFAULT,
    LOG_SEARCH_TIMEOUT_S_DEFAULT,
    ODOO_LOG_ARCHIVE_DAYS_DEFAULT,
)
from .._safe_error import safe_error_response
from ._helpers import (
    _LIST_MAX,
    _SECRET_FIELDS,
    _TAG_MODEL_BY_SCOPE,
    _capped_search,
    _has_encrypted,
    _has_pat,
)

_logger = logging.getLogger(__name__)

# Mirrors the Selection on ``cloud.instance.domain.cert_resolver``.
_CERT_RESOLVERS = frozenset({'letsencrypt', 'custom', 'none'})


def _domain_vals(payload):
    """Normalise one domain entry from the SPA into ORM values.

    ``cert_resolver`` is clamped to the model's Selection rather than
    passed through: the field used to be a free Char, so a cached SPA
    bundle or a hand-made RPC call can still send a value outside the
    domain. Clamping degrades it to the default instead of raising a 500
    on what is, from the caller's side, a stale client.

    :param dict payload: one entry of the request's ``domains`` list
    :returns: dict of values for ``cloud.instance.domain``
    """
    resolver = (payload.get('cert_resolver') or '').strip()
    return {
        'hostname': (payload.get('hostname') or '').strip(),
        'redirect_to': (payload.get('redirect_to') or '').strip(),
        'cert_resolver': (
            resolver if resolver in _CERT_RESOLVERS else 'letsencrypt'
        ),
        'redirect_permanent': bool(payload.get('redirect_permanent')),
    }


class CrudMixin:
    """Projects, hosts, instances, tags, users, secrets, dashboard,
    alerts, conflict resolution, general settings."""

    # Tag scope map kept on the class for subclass overrides.
    _TAG_MODEL_BY_SCOPE = _TAG_MODEL_BY_SCOPE

    @http.route(['/cloud/get_config'], type='jsonrpc', auth='user')
    def cloud_get_config(self):
        """Return feature flags and config for the SPA.

        Dependent modules override this method and call super() to inject
        additional feature flags. Example::

            def cloud_get_config(self):
                config = super().cloud_get_config()
                config['features']['my_feature'] = True
                return config
        """
        perms = self._sec()._get_user_permissions()
        user = request.env.user
        # Sidebar count badges. search_count honours record rules, so each
        # number reflects only what this user may see (and we gate by the
        # same permission flags that gate the nav items themselves).
        nav_counts = {'projects': request.env['cloud.project'].search_count([])}
        if perms.get('can_manage_hosts'):
            nav_counts['hosts'] = request.env['cloud.host'].search_count([])
        if perms.get('can_manage_settings'):
            nav_counts['backups'] = request.env['cloud.backup.backend'].search_count([])
        Settings = request.env['cloud.settings'].sudo()
        return {
            'features': {
                # The three axes of what this panel can do with
                # observability — collect / dashboards / configure. One
                # descriptor rather than a flag per screen: the two flat
                # booleans this replaces were read by four surfaces that
                # each picked a different one, and a tenant panel ended
                # up offering a Monitoring entry whose only message was
                # "configure it in Settings" — the one tab it hides.
                # See cloud.settings._observability_capabilities.
                'observability': Settings._observability_capabilities(),
            },
            'role': perms.pop('role', 'stakeholder'),
            'permissions': perms,
            'nav_counts': nav_counts,
            'user': {
                'name': user.name or user.login or '',
                'login': user.login or '',
                'avatar_url': (
                    f'/web/image?model=res.users'
                    f'&id={user.id}&field=image_128'
                ),
            },
        }

    @http.route(['/cloud/global_search'], type='jsonrpc', auth='user')
    def cloud_global_search(self, query=''):
        """Cross-entity search for the header search box. Returns matching
        projects, instances and (if permitted) hosts. ``search()`` honours
        record rules, so results respect each user's access."""
        q = (query or '').strip()
        if len(q) < 2:
            return {'results': []}
        perms = self._sec()._get_user_permissions()
        results = [
            {'type': 'project', 'label': p.name, 'sublabel': 'Project',
             'route': 'project_detail', 'params': {'project_id': p.id}}
            for p in request.env['cloud.project'].search([('name', 'ilike', q)], limit=6)
        ]
        for i in request.env['cloud.instance'].search(
                ['|', ('name', 'ilike', q), ('domain', 'ilike', q)], limit=8):
            sub = i.project_id.name or ''
            if i.domain:
                sub = (sub + ' · ' + i.domain) if sub else i.domain
            results.append({
                'type': 'instance', 'label': i.name, 'sublabel': sub,
                'route': 'instance_detail',
                'params': {'project_id': i.project_id.id, 'instance_id': i.id},
            })
        if perms.get('can_manage_hosts'):
            for h in request.env['cloud.host'].search([('name', 'ilike', q)], limit=5):
                results.append({
                    'type': 'host', 'label': h.name, 'sublabel': 'Host',
                    'route': 'host_detail', 'params': {'host_id': h.id},
                })
        return {'results': results}

    @http.route(['/cloud/get_projects'], type='jsonrpc', auth='user')
    def cloud_get_projects(self):
        projects, total, truncated, limit = _capped_search(
            request.env['cloud.project'], order='name',
        )
        items = []
        for p in projects:
            prod = p.instance_ids.filtered(lambda i: i.environment == 'production')
            first_prod_id = prod[:1].id if prod else False
            items.append({
                'id': p.id,
                'name': p.name,
                'description': p.description,
                'odoo_version': p.odoo_version or '',
                'status': p.status,
                'instance_count': len(p.instance_ids),
                'environments': p.instance_ids.mapped('environment'),
                'first_production_instance_id': first_prod_id,
                'tags': [
                    {'id': t.id, 'name': t.name, 'color': t.color}
                    for t in p.tag_ids
                ],
            })
        return {
            'items': items,
            'total': total,
            'truncated': truncated,
            'limit': limit,
        }

    # Map tag scope → tag model. Each scope has its own model to keep
    # tags of one entity from polluting another's tag cloud.
    _TAG_MODEL_BY_SCOPE = {
        'project':  'cloud.tag',
        'host':     'cloud.host.tag',
        'instance': 'cloud.instance.tag',
    }

    @http.route(['/cloud/get_tags'], type='jsonrpc', auth='user')
    def cloud_get_tags(self, scope='project'):
        model = self._TAG_MODEL_BY_SCOPE.get(scope, 'cloud.tag')
        # Defensive cap: tags are naturally bounded (tens in practice) but
        # the cap prevents a runaway script from tanking the autocomplete.
        tags = request.env[model].search([], limit=_LIST_MAX, order='name')
        payload = {
            'tags': [
                {'id': t.id, 'name': t.name, 'color': t.color} for t in tags
            ],
        }
        # Legacy contract: project scope also returns the defaults used by
        # new_project form. Other scopes don't need it.
        if scope == 'project':
            defaults = request.env['cloud.project'].default_get(
                ['pip_dependencies', 'odoo_version']
            )
            payload['project_defaults'] = {
                'pip_dependencies': defaults.get('pip_dependencies', ''),
                'odoo_version': defaults.get('odoo_version', '19.0'),
            }
        return payload

    @http.route(['/cloud/get_odoo_versions'], type='jsonrpc', auth='user')
    def cloud_get_odoo_versions(self):
        """Return the supported Odoo series for the version pickers.

        Single source of truth: the ``odoo_version`` Selection shared by
        ``cloud.project`` / ``cloud.instance``. Serving it here keeps the
        SPA pickers from hard-coding their own copy of the list.
        """
        selection = (
            request.env['cloud.instance']._fields['odoo_version'].selection
        )
        return {'odoo_versions': [code for code, _label in selection]}

    @http.route(['/cloud/get_users'], type='jsonrpc', auth='user')
    def cloud_get_users(self, search='', **kw):
        """Search internal users for member picker."""
        self._sec()._check_cloud_group('group_cloud_project_manager')
        # No sudo: PM+ already has read on res.users via implied groups,
        # and Odoo's standard res.users record rules scope what they
        # can see. The previous sudo() returned every internal user
        # in the database — useful for targeted phishing if the picker
        # search field accepts ``@``.
        domain = [('share', '=', False)]
        if search:
            domain.append(('name', 'ilike', search))
        users = request.env['res.users'].search(domain, limit=20)
        return [{'id': u.id, 'name': u.name, 'email': u.email or ''} for u in users]

    @http.route(['/cloud/create_tag'], type='jsonrpc', auth='user')
    def cloud_create_tag(self, name, scope='project'):
        # Consultant+ only: tags label projects / hosts / instances and
        # are visible across the SPA. Without a gate any internal user
        # could spam-create tags (table-bloat DoS) and pollute the
        # autocomplete dropdowns of every project / host / instance.
        self._sec()._check_cloud_group('group_cloud_consultant')
        name = name.strip()
        if not name:
            return {'ok': False, 'error': _('Tag name cannot be empty')}
        model = self._TAG_MODEL_BY_SCOPE.get(scope, 'cloud.tag')
        Tag = request.env[model]
        existing = Tag.search([('name', '=ilike', name)], limit=1)
        if existing:
            return {
                'id': existing.id, 'name': existing.name,
                'color': existing.color,
            }
        total = Tag.search_count([])
        tag = Tag.create({'name': name, 'color': total % 10})
        return {'id': tag.id, 'name': tag.name, 'color': tag.color}

    @http.route(['/cloud/get_hosts'], type='jsonrpc', auth='user')
    def cloud_get_hosts(self):
        hosts, total, truncated, limit = _capped_search(
            request.env['cloud.host'], order='name',
        )
        autoassign = (
            request.env['ir.config_parameter'].sudo()
            .get_param('incubacloud.host_autoassign', '0') == '1'
        )
        # Non-managers reach this endpoint only through the instance
        # move-host picker, which needs id/name/capacity — not the SSH
        # reconnaissance fields. Redact ip/port/user/login_type unless the
        # caller manages hosts, so a stakeholder cannot enumerate every
        # host's SSH endpoint.
        is_manager = self._sec()._has_cloud_group('group_cloud_manager')
        return {
            'autoassign_enabled': autoassign,
            'total': total,
            'truncated': truncated,
            'limit': limit,
            'hosts': [
                {
                    'id': host.id,
                    'name': host.name,
                    'type': host.type,
                    'status': host.status,
                    'description': host.description,
                    'tags': [
                        {'id': t.id, 'name': t.name, 'color': t.color}
                        for t in host.tag_ids
                    ],
                    'ip_address': host.ip_address if is_manager else '',
                    'port': host.port if is_manager else 0,
                    'user': host.user if is_manager else '',
                    'login_type': host.login_type if is_manager else '',
                    'has_password': _has_encrypted(host, 'password'),
                    'has_key_file': _has_encrypted(host, 'key_file'),
                    'has_known_hosts_key':
                        _has_encrypted(host, 'known_hosts_key'),
                    'known_hosts_fingerprint':
                        host.known_hosts_fingerprint if is_manager else '',
                    # Whether this host is actually reporting metrics.
                    # Without it on screen, an unmonitored host is
                    # indistinguishable from a monitored one — which is
                    # what made the old manual enrolment so confusing.
                    'metrics_agents_state': host.metrics_agents_state,
                    'metrics_last_seen': (
                        host.metrics_last_seen.isoformat()
                        if host.metrics_last_seen else ''
                    ),
                    'cpu_cores': host.cpu_cores,
                    'ram_total_gb': host.ram_total_gb,
                    'disk': round(host.disk_usage),
                    'disk_free_gb': round(host.disk_free_gb, 1),
                    'last_probed': host.last_probed,
                    'instance_count': len(host.instance_ids),
                    'traefik_deployed': host.traefik_deployed,
                    'exclude_from_autoassign': host.exclude_from_autoassign,
                    'allocated_cpus': round(host.allocated_cpus, 2),
                    'allocated_ram_gb': round(host.allocated_ram_gb, 2),
                    'available_cpus': round(host.available_cpus, 2),
                    'available_ram_gb': round(host.available_ram_gb, 2),
                    'usage_ratio': round(host.usage_ratio or 0.0, 4),
                    'alerts': [
                        {
                            'code': a.code,
                            'message': a.message,
                            'level': a.level,
                        }
                        for a in host.alert_ids.filtered(
                            lambda a: a.state == 'active'
                        )
                    ],
                }
                for host in hosts
            ],
        }

    @http.route(['/cloud/get_dashboard'], type='jsonrpc', auth='user')
    def cloud_get_dashboard(self):
        env = request.env
        # Dashboard only needs counts for hosts/instances/projects. Using
        # search_count avoids loading thousands of records into memory.
        proj_total = env['cloud.project'].search_count([])
        host_total = env['cloud.host'].search_count([])
        inst_total = env['cloud.instance'].search_count([])
        active_alerts = env['cloud.alert'].search(
            [('state', '=', 'active')], limit=_LIST_MAX,
        )
        alerts_total = env['cloud.alert'].search_count(
            [('state', '=', 'active')],
        )
        CloudJob = env['cloud.job']
        recent_jobs = CloudJob.search(
            [('job_type_id.code', 'not in', CloudJob._hidden_job_types)],
            order='create_date desc', limit=10,
        )
        return {
            'counts': {
                'projects': proj_total,
                'hosts': host_total,
                'instances': inst_total,
                'alerts': alerts_total,
            },
            'truncated': alerts_total > _LIST_MAX,
            'limit': _LIST_MAX,
            'alerts': [
                {
                    'id': a.id,
                    'code': a.code,
                    'host_id': a.host_id.id,
                    'instance_id': a.instance_id.id,
                    'project_id': a.instance_id.project_id.id if a.instance_id else False,
                    'host': (
                        a.host_id.name
                        if a.host_id
                        else f"{a.instance_id.project_id.name} / {a.instance_id.name}"
                    ),
                    'job_id': a.job_id.id,
                    'message': a.message,
                    'level': a.level,
                }
                for a in active_alerts
            ],
            'recent_jobs': [
                {
                    'id': j.id,
                    'name': j.name,
                    'host': j.host_id.name,
                    'state': j.state,
                    'create_date': j.create_date,
                    'job_type': j.job_type_id.code,
                }
                for j in recent_jobs
            ],
        }

    @http.route(['/cloud/get_alert_count'], type='jsonrpc', auth='user')
    def cloud_get_alert_count(self):
        count = request.env['cloud.alert'].search_count([('state', '=', 'active')])
        return {'count': count}

    @http.route(['/cloud/dismiss_alert'], type='jsonrpc', auth='user')
    def cloud_dismiss_alert(self, alert_id):
        # Consultant+ only: dismissing alerts is an operational
        # decision (especially for ``pip_conflict`` / ``addon_conflict``
        # which gate deploys), so stakeholders cannot silently mute
        # them. Per-project scoping is still enforced by the record
        # rule on cloud.alert via the ``write`` access check below.
        self._sec()._check_cloud_group('group_cloud_consultant')
        alert = request.env['cloud.alert'].browse(alert_id)
        if not alert.exists():
            return {'ok': False, 'error': _('Alert not found')}
        alert.check_access('write')
        alert.write({'state': 'dismissed'})
        return {'ok': True}

    @http.route(['/cloud/compare_sync'], type='jsonrpc', auth='user')
    def cloud_compare_sync(self, instance_id):
        """Compare instance deps/repos with its project template."""
        # Consultant+ only: same gate as ``cloud_apply_sync`` so the
        # diff stays out of stakeholder hands.
        self._sec()._check_cloud_group('group_cloud_consultant')
        try:
            instance_id = int(instance_id)
        except (TypeError, ValueError):
            return {'ok': False, 'error': _('Invalid instance id')}
        inst = request.env['cloud.instance'].browse(instance_id)
        if not inst.exists() or not inst.project_id:
            return {'ok': False, 'error': _('Instance or project not found')}
        inst.check_access('read')
        try:
            diff = compare_instance_project(inst)
        except Exception as exc:
            return safe_error_response(
                exc, _("Failed to compare instance with project"),
            )
        return {'ok': True, 'diff': diff}

    @http.route(['/cloud/apply_sync'], type='jsonrpc', auth='user')
    def cloud_apply_sync(self, instance_id, actions):
        """Apply user-selected sync actions between instance and project."""
        # Consultant+ only: ``apply_sync`` mutates the instance's
        # ``pip_dependencies`` and ``repo_ids`` (same blast radius as
        # ``cloud_save_instance``), so the gate must match.
        self._sec()._check_cloud_group('group_cloud_consultant')
        try:
            instance_id = int(instance_id)
        except (TypeError, ValueError):
            return {'ok': False, 'error': _('Invalid instance id')}
        inst = request.env['cloud.instance'].browse(instance_id)
        if not inst.exists() or not inst.project_id:
            return {'ok': False, 'error': _('Instance or project not found')}
        inst.check_access('write')
        try:
            apply_sync(inst, actions)
        except Exception:
            _logger.exception("apply_sync failed for instance %s", instance_id)
            return {'ok': False, 'error': _('An internal error occurred. Check server logs.')}
        return {'ok': True}

    @http.route(['/cloud/get_job_brief'], type='jsonrpc', auth='user')
    def cloud_get_job_brief(self, job_id):
        """Minimal job info for the live toast: the bus only ships
        ``{id, state}`` (it ignores record rules), so the client comes
        back through this ACL-checked path for anything displayable.
        Returns ``{'ok': False}`` for jobs the user cannot read and for
        hidden background types — neither should ever toast.
        """
        try:
            job_id = int(job_id)
        except (TypeError, ValueError):
            return {'ok': False}
        job = request.env['cloud.job'].browse(job_id)
        try:
            if not job.exists():
                return {'ok': False}
            job.check_access('read')
        except AccessError:
            return {'ok': False}
        if job.job_type_id.code in request.env['cloud.job']._get_hidden_job_types():
            return {'ok': False}
        # Muted projects never toast — same personal mute list the
        # email/digest channels honour.
        if request.env['cloud.job']._job_muted_for(job, request.env.user):
            return {'ok': False}
        return {
            'ok': True,
            'id': job.id,
            'name': job.name,
            'state': job.state,
        }

    @http.route(['/cloud/dismiss_all_alerts'], type='jsonrpc', auth='user')
    def cloud_dismiss_all_alerts(self, level_filter=None):
        """Bulk-dismiss the active non-conflict alerts visible to the
        caller. Same consultant gate as the single dismiss."""
        self._sec()._check_cloud_group('group_cloud_consultant')
        count = request.env['cloud.alert'].action_dismiss_all(
            level_filter=level_filter,
        )
        return {'ok': True, 'count': count}

    @http.route(['/cloud/get_alert_history'], type='jsonrpc', auth='user')
    def cloud_get_alert_history(self, state_filter='all', level_filter='all',
                                offset=0, limit=20):
        domain = [] if state_filter == 'all' else [('state', '=', state_filter)]
        if level_filter in ('warning', 'critical'):
            domain.append(('level', '=', level_filter))
        try:
            offset = max(0, int(offset))
            limit = min(100, max(1, int(limit)))
        except (TypeError, ValueError):
            offset, limit = 0, 20
        Alert = request.env['cloud.alert']
        total = Alert.search_count(domain)
        alerts = Alert.search(
            domain, order='create_date desc', offset=offset, limit=limit,
        )
        entries = [
            {
                'id': a.id,
                'code': a.code,
                'level': a.level,
                'state': a.state,
                'message': a.message,
                'create_date': a.create_date,
                'host': (
                    a.host_id.name
                    if a.host_id
                    else (
                        f"{a.instance_id.project_id.name} / {a.instance_id.name}"
                        if a.instance_id
                        else (a.project_id.name or '—')
                    )
                ),
                'target': (
                    a.host_id.name if a.host_id
                    else (
                        f"{a.instance_id.project_id.name} / {a.instance_id.name}"
                        if a.instance_id and a.instance_id.project_id
                        else (a.instance_id.name if a.instance_id
                              else (a.project_id.name or '—'))
                    )
                ),
                'job_id': a.job_id.id,
                'conflict_data': a.conflict_data or [],
                'payload': a.payload or None,
                'instance_id': a.instance_id.id or False,
                'project_id': (
                    a.instance_id.project_id.id if a.instance_id
                    else (a.project_id.id or False)
                ),
            }
            for a in alerts
        ]
        return {'total': total, 'alerts': entries}

    @http.route(['/cloud/resolve_pip_conflict'], type='jsonrpc', auth='user')
    def cloud_resolve_pip_conflict(self, alert_id, resolutions):
        """Resolve a pip dependency conflict alert.

        alert_id: int
        resolutions: {package_name_lowercase: chosen_spec_string}
        Returns {'ok': bool, 'error'?: str}
        """
        # Consultant+ only: resolving a conflict mutates
        # ``pip_dependencies`` of the parent (same blast radius as
        # ``cloud_save_instance``) and unblocks the linked deploy job.
        # Per-record scoping is enforced by ``check_access('write')``
        # on the alert below.
        self._sec()._check_cloud_group('group_cloud_consultant')
        try:
            alert_id = int(alert_id)
        except (TypeError, ValueError):
            return {'ok': False, 'error': _('Invalid alert id')}
        alert = request.env['cloud.alert'].browse(alert_id)
        if (not alert.exists()
                or alert.code != 'pip_conflict'
                or alert.state != 'active'):
            return {
                'ok': False, 'error': _('Alert not found or already resolved'),
            }
        alert.check_access('write')
        parent = alert.instance_id or alert.project_id
        if not parent:
            return {'ok': False, 'error': _('No parent record found')}

        # Replace each conflict block with the user's chosen spec.
        # Track seen names to deduplicate if the same block appears twice.
        new_text = parent.pip_dependencies or ''
        sources = dict(parent.pip_dependency_sources or {})
        for m in list(CONFLICT_RE.finditer(parent.pip_dependencies or '')):
            existing_line = m.group('existing_line').strip()
            parsed = _parse_req_line(existing_line)
            if parsed:
                chosen = resolutions.get(parsed[0])
                if chosen is not None:
                    new_text = new_text.replace(m.group(0), chosen, 1)
                    # Siding with the repo hands the line back to it, so
                    # its next bump applies on its own; any other answer
                    # (the stored spec, or a third one typed here) makes
                    # the line the operator's and freezes it against
                    # upstream until they say otherwise.
                    repo_key = ''
                    if chosen.strip() == m.group('incoming_line').strip():
                        repo_key = repo_key_for_source_label(
                            parent.repo_ids, m.group('incoming_src'),
                        )
                    if repo_key:
                        sources[parsed[0]] = {
                            'repo': repo_key,
                            'spec': chosen.strip(),
                            'label': m.group('incoming_src').strip(),
                        }
                    else:
                        sources.pop(parsed[0], None)

        parent.with_context(pip_provenance_managed=True).write({
            'pip_dependencies': new_text,
            'pip_dependency_sources': sources,
        })
        alert.state = 'dismissed'

        # Unblock the linked job only if all conflicts are now resolved
        if not detect_pip_conflicts(new_text):
            blocked_job = request.env['cloud.job'].search(
                [('blocked_alert_id', '=', alert.id)], limit=1,
            )
            if blocked_job:
                blocked_job.unblock_and_enqueue()
        return {'ok': True}

    @http.route(['/cloud/resolve_addon_conflict'], type='jsonrpc', auth='user')
    def cloud_resolve_addon_conflict(self, alert_id, resolutions):
        """Resolve an addon conflict alert.

        alert_id: int
        resolutions: {addon_name: winner_repo_alias}
            For each conflicting addon, the user picks which repo keeps it.
            The addon is added to the excludes of all other repos involved.
        Returns {'ok': bool, 'error'?: str}
        """
        # Consultant+ only: same blast radius as editing ``repo.excludes``
        # directly. Per-record scoping enforced via the alert's
        # write access below.
        self._sec()._check_cloud_group('group_cloud_consultant')
        try:
            alert_id = int(alert_id)
        except (TypeError, ValueError):
            return {'ok': False, 'error': _('Invalid alert id')}
        alert = request.env['cloud.alert'].browse(alert_id)
        if (not alert.exists()
                or alert.code != 'addon_conflict'
                or alert.state != 'active'):
            return {'ok': False, 'error': _('Alert not found or already resolved')}
        alert.check_access('write')
        inst = alert.instance_id
        if not inst:
            return {'ok': False, 'error': _('No instance linked to this alert')}

        # For each repo, compute what modules need to be added to its excludes.
        for repo in inst.repo_ids:
            alias = _repo_alias(repo.url)
            existing = {m.strip() for m in (repo.excludes or '').split(',') if m.strip()}
            for conflict in (alert.conflict_data or []):
                addon = conflict['addon']
                winner = resolutions.get(addon)
                # Add to excludes if this repo is a loser and involved in the conflict
                if winner and alias != winner and alias in conflict.get('repos', []):
                    existing.add(addon)
            repo.excludes = ','.join(sorted(existing)) if existing else ''

        alert.state = 'dismissed'
        blocked_job = request.env['cloud.job'].search(
            [('blocked_alert_id', '=', alert.id)], limit=1,
        )
        if blocked_job:
            blocked_job.unblock_and_enqueue()
        return {'ok': True}

    @http.route(['/cloud/get_secret'], type='jsonrpc', auth='user')
    def cloud_get_secret(self, model, record_id, field):
        """Return the plain-text value of an encrypted password field.

        Only fields explicitly listed in _SECRET_FIELDS are accessible.
        The user must have write access to the record (same check as saving).
        """
        self._sec()._check_cloud_group('group_cloud_developer')
        allowed = _SECRET_FIELDS.get(model)
        if not allowed or field not in allowed:
            return {'ok': False, 'error': _('Field not allowed')}
        record = request.env[model].browse(record_id)
        if not record.exists():
            return {'ok': False, 'error': _('Record not found')}
        # Require write access as a proxy for "trusted user"
        record.check_access('write')
        value = getattr(record, field, None) or ''
        return {'value': value}
    @http.route(['/cloud/get_host'], type='jsonrpc', auth='user')
    def cloud_get_host(self, host_id):
        # Manager-gated like the host detail editor it feeds (save/delete
        # are already manager-only). Exposes the full SSH endpoint config.
        self._sec()._check_can_manage_hosts()
        host = request.env['cloud.host'].browse(host_id)
        if not host.exists():
            return {'ok': False, 'error': _('Host not found')}
        return {
            'id': host.id,
            'name': host.name,
            'type': host.type,
            'status': host.status,
            'ip_address': host.ip_address,
            'port': host.port,
            'user': host.user,
            'login_type': host.login_type,
            'has_password': _has_encrypted(host, 'password'),
            'has_key_file': _has_encrypted(host, 'key_file'),
            'has_known_hosts_key': _has_encrypted(host, 'known_hosts_key'),
            'known_hosts_fingerprint': host.known_hosts_fingerprint,
            'revoked_key_fingerprint': host.revoked_key_fingerprint or '',
            'description': host.description,
            'tags': [
                {'id': t.id, 'name': t.name, 'color': t.color}
                for t in host.tag_ids
            ],
            'all_tags': [
                {'id': t.id, 'name': t.name, 'color': t.color}
                for t in request.env['cloud.host.tag'].search(
                    [], limit=_LIST_MAX, order='name',
                )
            ],
            'cpu_cores': host.cpu_cores,
            'ram_total_gb': host.ram_total_gb,
            'disk': round(host.disk_usage),
            'disk_free_gb': round(host.disk_free_gb, 1),
            'last_probed': host.last_probed,
            'instance_count': len(host.instance_ids),
            'traefik_deployed': host.traefik_deployed,
            'config_dirty': host.config_dirty,
            'template_drift': host.template_drift,
            'template_drift_details': host.template_drift_details or '',
            'wildcard_domain': host.wildcard_domain or '',
            'has_traefik_panel_password':
                _has_encrypted(host, 'traefik_panel_password'),
            'traefik_config_yml': host.traefik_config_yml or '',
            'traefik_inverseproxy_yaml': host.traefik_inverseproxy_yaml or '',
            'traefik_yml': host.traefik_yml or '',
            'exclude_from_autoassign': host.exclude_from_autoassign,
            'http_conn_rate': host.http_conn_rate,
            'behind_cdn': host.behind_cdn,
            'trusted_proxy_ranges': host.trusted_proxy_ranges or '',
            'block_direct_access': host.block_direct_access,
            # The list the host is actually filtered against, and where
            # it comes from. The field above is only the override, so
            # showing it alone would say nothing about what applies.
            'effective_trusted_proxy_ranges':
                host._effective_trusted_proxy_ranges(),
            'trusted_proxy_source': host._trusted_proxy_source(),
            'trusted_proxies_shipped': host.trusted_proxies_shipped or '',
            'allocated_cpus': round(host.allocated_cpus, 2),
            'allocated_ram_gb': round(host.allocated_ram_gb, 2),
            'available_cpus': round(host.available_cpus, 2),
            'available_ram_gb': round(host.available_ram_gb, 2),
            'whitelist': host.whitelist_ids.mapped('hostname'),
            'custom_actions': [
                {
                    'code': jt.code,
                    'name': jt.name,
                    'action_icon': jt.action_icon or 'fa-cog',
                    'action_confirm': jt.action_confirm or '',
                }
                for jt in request.env['cloud.job.type'].search([
                    ('show_as_action', '=', True),
                    ('apply_to', '=', 'host'),
                ], order='action_order, id')
            ],
        }

    _HOST_ALLOWED = {
        'name', 'type', 'ip_address', 'port', 'user', 'login_type',
        'password', 'key_file', 'description', 'tag_ids',
        'wildcard_domain', 'traefik_panel_password',
        'traefik_config_yml', 'traefik_inverseproxy_yaml', 'traefik_yml',
        'exclude_from_autoassign', 'http_conn_rate',
        'trusted_proxy_ranges', 'block_direct_access', 'behind_cdn',
    }

    @http.route(['/cloud/host_defaults'], type='jsonrpc', auth='user')
    def cloud_host_defaults(self):
        self._sec()._check_can_manage_hosts()
        Host = request.env['cloud.host']
        defaults = Host.default_get([
            'traefik_config_yml', 'traefik_inverseproxy_yaml', 'traefik_yml',
        ])
        return {
            'traefik_config_yml': defaults.get('traefik_config_yml', ''),
            'traefik_inverseproxy_yaml': defaults.get('traefik_inverseproxy_yaml', ''),
            'traefik_yml': defaults.get('traefik_yml', ''),
        }

    @http.route(['/cloud/create_host'], type='jsonrpc', auth='user')
    def cloud_create_host(self, vals):
        self._sec()._check_can_manage_hosts()
        safe = {k: v for k, v in vals.items() if k in self._HOST_ALLOWED}
        if safe.get('port'):
            safe['port'] = int(safe['port'])
        if 'tag_ids' in safe:
            safe['tag_ids'] = [fields.Command.set(safe['tag_ids'] or [])]
        host = request.env['cloud.host'].create(safe)
        return {'id': host.id, 'name': host.name}

    @http.route(['/cloud/delete_host'], type='jsonrpc', auth='user')
    def cloud_delete_host(self, host_id):
        self._sec()._check_can_manage_hosts()
        host = request.env['cloud.host'].browse(host_id)
        if not host.exists():
            return {'ok': False, 'error': _('Host not found')}
        if host.instance_ids:
            return {'ok': False, 'error': _('Host still has instances. Delete all instances first.')}
        if not host.traefik_deployed:
            # Nothing was deployed remotely — no SSH cleanup needed.
            # Two sub-cases by job history:
            #
            #   * The host has zero ``cloud.job`` rows referencing it
            #     (truly-untouched fixture / cancel-before-provision):
            #     ``unlink`` is safe and keeps the table clean.
            #
            #   * The host already accumulated jobs (e.g. on-demand VPS
            #     where ``tenant_vps_provision`` succeeded but the
            #     chained ``host_hardening`` + ``full_setup`` never ran,
            #     so Traefik is not deployed yet but provision history
            #     exists): ``unlink`` would violate the
            #     ``cloud_job.host_id`` FK constraint (required + no
            #     ``ondelete``). Archive instead — same semantics the
            #     ``delete_host`` executor uses on the deployed branch,
            #     preserves the job history, and ``write({'active':
            #     False})`` still fires ``_release_external_resources``
            #     so downstream modules (tenant on-demand VPS release,
            #     DNS, etc.) clean up provider-side state.
            has_jobs = bool(request.env['cloud.job'].sudo().search_count(
                [('host_id', '=', host.id)],
            ))
            if has_jobs:
                host.write({'active': False})
            else:
                host.unlink()
            return {'ok': True}
        job_id = request.env['cloud.job'].enqueue(host_id, False, 'delete_host')
        return {'job_id': job_id}

    @http.route(['/cloud/trust_host_key'], type='jsonrpc', auth='user', methods=['POST'])
    def cloud_trust_host_key(self, host_id):
        """Connect once (without verification) to capture and store the server
        host public key.  Subsequent connections will verify against it."""
        self._sec()._check_can_manage_hosts()
        # sudo: trusted endpoint (manager-only gate); secret fields now
        # require group_cloud_developer which manager inherits, but using
        # sudo explicitly documents intent and survives future changes.
        host = request.env['cloud.host'].sudo().browse(host_id)
        if not host.exists():
            return {'ok': False, 'error': _('Host not found')}
        try:
            captured = host._capture_known_host_key()
        except asyncssh.Error:
            _logger.exception("trust_host_key SSH error for host %s", host_id)
            return {'ok': False, 'error': _('SSH connection failed. Check host credentials and network.')}
        except Exception:
            _logger.exception("trust_host_key failed for host %s", host_id)
            return {'ok': False, 'error': _('Connection failed. Check host credentials and network.')}
        # The verdict travels to the panel: whether this key matches the one
        # revoked by the last endpoint change is the only machine-identity
        # check available, so it has to reach the operator who just clicked.
        return {
            'ok': True,
            'fingerprint': captured['fingerprint'],
            'previous_fingerprint': captured['previous_fingerprint'],
            'changed': captured['changed'],
        }

    @http.route(['/cloud/save_host'], type='jsonrpc', auth='user')
    def cloud_save_host(self, host_id, vals):
        self._sec()._check_can_manage_hosts()
        host = request.env['cloud.host'].browse(host_id)
        if not host.exists():
            return {'ok': False, 'error': _('Host not found')}
        safe_vals = {k: v for k, v in vals.items() if k in self._HOST_ALLOWED}
        # Only update key_file if a new one was uploaded
        if not safe_vals.get('key_file'):
            safe_vals.pop('key_file', None)
        if 'tag_ids' in safe_vals:
            safe_vals['tag_ids'] = [
                fields.Command.set(safe_vals['tag_ids'] or [])
            ]
        host.write(safe_vals)

        # Sync whitelist entries when provided.
        # Use a direct search instead of host.whitelist_ids to avoid
        # reading a stale ORM cache on a freshly-browsed record.
        if 'whitelist' in vals:
            hostnames = [
                h.strip() for h in (vals['whitelist'] or [])
                if h and h.strip()
            ]
            request.env['cloud.host.whitelist'].search(
                [('host_id', '=', host.id)]
            ).unlink()
            if hostnames:
                request.env['cloud.host.whitelist'].create([
                    {'host_id': host.id, 'hostname': h, 'sequence': i * 10}
                    for i, h in enumerate(hostnames, 1)
                ])

        return {'ok': True}

    @http.route(['/cloud/setup_whitelist'], type='jsonrpc', auth='user')
    def cloud_setup_whitelist(self, host_id):
        self._sec()._check_can_manage_hosts()
        host = request.env['cloud.host'].browse(host_id)
        if not host.exists():
            return {'ok': False, 'error': _('Host not found')}
        job_id = request.env['cloud.job'].enqueue(
            host_id, False, 'setup_whitelist'
        )
        return {'job_id': job_id}
    # ── Project detail endpoints ────────────────────────────────────────────

    @http.route(['/cloud/get_project'], type='jsonrpc', auth='user')
    def cloud_get_project(self, project_id):
        project = request.env['cloud.project'].browse(project_id)
        if not project.exists():
            return {'ok': False, 'error': _('Project not found')}
        all_tags = request.env['cloud.tag'].search(
            [], limit=_LIST_MAX, order='name',
        )
        return {
            'id': project.id,
            'name': project.name,
            'description': project.description or '',
            'project_author': project.project_author or 'IncubaCloud',
            'project_license': project.project_license or 'BSL-1.0',
            'status': project.status,
            'instance_count': len(project.instance_ids),
            'tags': [
                {'id': t.id, 'name': t.name, 'color': t.color}
                for t in project.tag_ids
            ],
            'all_tags': [
                {'id': t.id, 'name': t.name, 'color': t.color}
                for t in all_tags
            ],
            'odoo_version': project.odoo_version or '19.0',
            'odoo_commit_sha': project.odoo_commit_sha or '',
            'odoo_initial_lang': (
                project.odoo_initial_lang.id if project.odoo_initial_lang else None
            ),
            'pip_dependencies': project.pip_dependencies or '',
            'apt_dependencies': project.apt_dependencies or '',
            'member_ids': [{'id': u.id, 'name': u.name} for u in project.member_ids],
            'backup_backend_id': (
                project.backup_backend_id.id if project.backup_backend_id else None
            ),
            'repos': [
                {
                    'id': r.id,
                    'url': r.url,
                    'branch': r.branch or 'main',
                    'addons': r.addons or '',
                    'excludes': r.excludes or '',
                    'commit_sha': r.commit_sha or '',
                }
                for r in project.repo_ids
            ],
        }

    @http.route(['/cloud/create_project'], type='jsonrpc', auth='user')
    def cloud_create_project(self, vals):
        self._sec()._check_can_create_project()
        _PROJ_ALLOWED = {
            'name', 'description', 'project_author', 'project_license',
            'odoo_version', 'odoo_commit_sha', 'odoo_initial_lang',
            'pip_dependencies', 'apt_dependencies',
            'backup_backend_id',
        }
        repos = vals.pop('repos', None)
        tag_ids = vals.pop('tag_ids', None)
        safe = {k: v for k, v in vals.items() if k in _PROJ_ALLOWED}
        # Never override pip_dependencies with an empty string: let the ORM
        # default apply so every new project starts with the base packages.
        if not safe.get('pip_dependencies'):
            safe.pop('pip_dependencies', None)
        if tag_ids is not None:
            safe['tag_ids'] = [fields.Command.set(tag_ids)]
        project = request.env['cloud.project'].create(safe)
        # ── Create repos ─────────────────────────────────────────────────────
        if repos:
            Repo = request.env['cloud.project.repo'].with_context(
                skip_apply_requirements=True,
            )
            for seq, repo in enumerate(repos, start=10):
                if repo.get('url', '').strip():
                    Repo.create({
                        'project_id': project.id,
                        'sequence': seq,
                        'url': repo['url'].strip(),
                        'branch': repo.get('branch', 'main').strip() or 'main',
                        'addons': repo.get('addons', '').strip(),
                        'excludes': repo.get('excludes', '').strip(),
                        'commit_sha': repo.get('commit_sha', '').strip(),
                    })
            # ── Merge repo requirements into pip_dependencies ─────────────
            merged = project.pip_dependencies or ''
            for repo in repos:
                url = repo.get('url', '').strip()
                branch = (repo.get('branch') or 'main').strip() or 'main'
                if url:
                    content = fetch_requirements_txt(request.env, url, branch)
                    if content:
                        result = merge_pip_requirements(
                            merged, content, url, branch,
                        )
                        merged = result['content']
            if merged != (project.pip_dependencies or ''):
                project.pip_dependencies = merged
        # ── Pip conflict detection ────────────────────────────────────────
        conflicts = detect_pip_conflicts(project.pip_dependencies or '')
        if conflicts:
            create_pip_conflict_alert(
                request.env, conflicts, project_id=project.id,
            )
        return {'id': project.id, 'name': project.name}

    @http.route(['/cloud/save_project'], type='jsonrpc', auth='user')
    def cloud_save_project(self, project_id, vals):
        self._sec()._check_cloud_group('group_cloud_consultant')
        project = request.env['cloud.project'].browse(project_id)
        if not project.exists():
            return {'ok': False, 'error': _('Project not found')}
        repos = vals.pop('repos', None)
        tag_ids = vals.pop('tag_ids', None)
        member_ids = vals.pop('member_ids', None)
        _PROJ_ALLOWED = {
            'name', 'description', 'project_author', 'project_license',
            'odoo_version', 'odoo_commit_sha', 'odoo_initial_lang',
            'pip_dependencies', 'apt_dependencies',
            'backup_backend_id',
        }
        safe_vals = {k: v for k, v in vals.items() if k in _PROJ_ALLOWED}
        if tag_ids is not None:
            safe_vals['tag_ids'] = [fields.Command.set(tag_ids)]
        if member_ids is not None:
            safe_vals['member_ids'] = [fields.Command.set(member_ids)]
        if safe_vals:
            project.write(safe_vals)
        if repos is not None:
            project.repo_ids.unlink()
            Repo = request.env['cloud.project.repo'].with_context(
                skip_apply_requirements=True,
            )
            for seq, repo in enumerate(repos, start=10):
                if repo.get('url', '').strip():
                    Repo.create({
                        'project_id': project.id,
                        'sequence': seq,
                        'url': repo['url'].strip(),
                        'branch': repo.get('branch', 'main').strip() or 'main',
                        'addons': repo.get('addons', '').strip(),
                        'excludes': repo.get('excludes', '').strip(),
                        'commit_sha': repo.get('commit_sha', '').strip(),
                    })
        # ── Pip conflict detection ────────────────────────────────────────────
        pip_deps = project.pip_dependencies or ''
        conflicts = detect_pip_conflicts(pip_deps)
        Alert = request.env['cloud.alert']
        if conflicts:
            create_pip_conflict_alert(
                request.env, conflicts, project_id=project.id,
            )
        else:
            active = Alert.search([
                ('code', '=', 'pip_conflict'),
                ('project_id', '=', project.id),
                ('state', '=', 'active'),
            ], limit=1)
            if active:
                active.write({'state': 'dismissed'})
        return {'ok': True}

    @http.route(['/cloud/get_host_instances'], type='jsonrpc', auth='user')
    def cloud_get_host_instances(self, host_id):
        host = request.env['cloud.host'].browse(host_id)
        if not host.exists():
            return {'ok': False, 'error': _('Host not found')}
        is_developer = self._sec()._has_cloud_group('group_cloud_developer')
        return {
            'host_name': host.name,
            'instances': [
                {
                    'id': i.id,
                    'name': i.name,
                    'environment': i.environment,
                    'status': i.status,
                    'state': i.state,
                    'deployed': i.deployed,
                    'running': i.running,
                    'service_states': i.service_states or {},
                    'stop_is_expected': i.stop_is_expected,
                    'host': i.host_id.name if i.host_id else '',
                    'host_id': i.host_id.id if i.host_id else None,
                    'host_ip': (
                        i.host_id.ip_address
                        if (i.host_id and is_developer) else ''
                    ),
                    'host_user': (
                        i.host_id.user if (i.host_id and is_developer) else ''
                    ),
                    'host_port': (
                        i.host_id.port if (i.host_id and is_developer) else 22
                    ),
                    'db_name': i.postgres_dbname or 'prod',
                    'domain': i.domain or '',
                    'compose_services': i.compose_services or 'odoo,db',
                    'project_id': i.project_id.id if i.project_id else None,
                    'project_name': i.project_id.name if i.project_id else '',
                    'pr_number': i.pr_number or 0,
                }
                for i in host.instance_ids
            ],
        }

    @http.route(['/cloud/get_project_instances'], type='jsonrpc', auth='user')
    def cloud_get_project_instances(self, project_id):
        project = request.env['cloud.project'].browse(project_id)
        if not project.exists():
            return {'ok': False, 'error': _('Project not found')}
        CloudJob = request.env['cloud.job']
        is_developer = self._sec()._has_cloud_group('group_cloud_developer')
        instances = []
        for i in project.instance_ids:
            latest = CloudJob.search(
                [('instance_id', '=', i.id)],
                order='create_date desc', limit=1,
            )
            instances.append({
                'id': i.id,
                'name': i.name,
                'environment': i.environment,
                'status': i.status,
                'state': i.state,
                'deployed': i.deployed,
                'running': i.running,
                'service_states': i.service_states or {},
                'stop_is_expected': i.stop_is_expected,
                'host': i.host_id.name if i.host_id else '',
                'host_id': i.host_id.id if i.host_id else None,
                'host_ip': (
                    i.host_id.ip_address
                    if (i.host_id and is_developer) else ''
                ),
                'host_user': (
                    i.host_id.user if (i.host_id and is_developer) else ''
                ),
                'host_port': (
                    i.host_id.port if (i.host_id and is_developer) else 22
                ),
                'db_name': i.postgres_dbname or 'prod',
                'domain': i.domain or '',
                'compose_services': i.compose_services or 'odoo,db',
                'latest_job_id': latest.id if latest else None,
                'pr_number': i.pr_number or 0,
                # Lets the refresh dialog tell "restore from the latest
                # snapshot" apart from "there is no snapshot store, a
                # live dump is the only option".
                'effective_backup_backend_id': (
                    i.effective_backup_backend.id
                    if i.effective_backup_backend else None
                ),
            })
        return {
            'project_name': project.name,
            'instances': instances,
        }

    @http.route(['/cloud/get_archived_instances'], type='jsonrpc',
                auth='user')
    def cloud_get_archived_instances(self, project_id):
        """Archived instances of a project, with what their copy costs.

        Archiving sets ``active = False``, so these are invisible to
        every other listing — ``project.instance_ids`` skips them like
        any one2many. Without a route of their own an archived instance
        would be unreachable, which is why this ships together with the
        flag rather than after it.

        The size and the verification stamp are read from the record,
        never measured here: listing a bucket prefix per row would put a
        network call in the render path. A cron refreshes them and this
        reports what it last saw, including how long ago that was, so a
        stale figure is visible as stale rather than passing for current.

        Where the copy lives is manager-only, the same rule SEC-009 set
        for every other endpoint that could name a bucket: the frozen
        destination and the backend's name are exactly the metadata the
        backends list is gated on, and in SaaS that storage is ours, not
        the tenant's. Everyone who can see the project still sees that
        there is a copy, how big it is and when it was last checked —
        none of which says where it is.
        """
        project = request.env['cloud.project'].browse(project_id)
        if not project.exists():
            return {'ok': False, 'error': _('Project not found')}
        is_manager = self._sec()._has_cloud_group('group_cloud_manager')
        archived = request.env['cloud.instance'].with_context(
            active_test=False,
        ).search([
            ('project_id', '=', project_id),
            ('active', '=', False),
        ], order='name')
        return {
            'ok': True,
            'project_name': project.name,
            'instances': [{
                'id': i.id,
                'name': i.name,
                'environment': i.environment,
                'odoo_version': i.odoo_version or '',
                'archived_on': i.archived_at or i.write_date,
                'host_name': i.host_id.name or '',
                # The frozen path: where the copy actually is, whatever
                # the computed one would say now. Redacted below manager
                # — it names a bucket.
                'backup_dst': (
                    i.custom_backup_dst or '' if is_manager else ''
                ),
                'backup_backend_name': (
                    i.effective_backup_backend.name
                    if is_manager and i.effective_backup_backend else ''
                ),
                # False when archiving found no destination: the teardown
                # destroyed everything and there is nothing to revive
                # from. The view must not offer the button.
                'has_copy': bool(i.custom_backup_dst),
                # The cron's last reading, shipped with its timestamp so
                # the view can say how old it is instead of presenting a
                # week-old check as the current state.
                'copy_state': i.archive_copy_state or '',
                'copy_bytes': i.archive_copy_bytes or 0.0,
                'copy_checked_at': i.archive_copy_checked_at,
            } for i in archived],
        }

    @http.route(['/cloud/revive_instance'], type='jsonrpc', auth='user')
    def cloud_revive_instance(self, instance_id, host_id=None):
        """Bring an archived instance back and restore its copy.

        Gated as a deploy, not as a read: this builds an instance on a
        host and restores a database into it. ``browse`` without sudo on
        purpose, so the record rules that scope instances still apply —
        the archived flag hides a record from lists, it does not make it
        anyone's to revive.
        """
        self._sec()._check_can_deploy()
        inst = request.env['cloud.instance'].with_context(
            active_test=False,
        ).browse(instance_id)
        if not inst.exists():
            return {'ok': False, 'error': _('Instance not found')}
        try:
            job_ids = inst.revive(host_id=host_id)
        except UserError as exc:
            return {'ok': False, 'error': str(exc)}
        return {'ok': True, 'job_ids': job_ids}

    @http.route(['/cloud/delete_archived_instance'], type='jsonrpc',
                auth='user')
    def cloud_delete_archived_instance(self, instance_id, confirm_name=None):
        """Delete an archived instance and the copy it still owns.

        Manager-gated, and it asks for the name in writing. There is no
        undo behind this: the chain is emptied and the record removed,
        and unlike a live instance there is not even a running system to
        notice the mistake afterwards. The typing is checked here and
        not only in the browser, so a direct RPC call faces the same
        friction the dialog does.
        """
        self._sec()._check_cloud_group('group_cloud_manager')
        inst = request.env['cloud.instance'].with_context(
            active_test=False,
        ).browse(instance_id)
        if not inst.exists():
            return {'ok': False, 'error': _('Instance not found')}
        if (confirm_name or '').strip() != inst.name:
            return {'ok': False, 'error': _(
                'Type the instance name exactly to confirm.'
            )}
        try:
            job_ids = inst.delete_archived()
        except UserError as exc:
            return {'ok': False, 'error': str(exc)}
        return {'ok': True, 'job_ids': job_ids}

    _CREATE_INSTANCE_ALLOWED = {
        'name', 'project_id', 'host_id', 'environment',
        'odoo_version', 'odoo_commit_sha',
        'odoo_initial_lang', 'odoo_admin_password', 'odoo_proxy',
        'postgres_version', 'postgres_dbname', 'postgres_username', 'postgres_password',
        'pip_dependencies', 'apt_dependencies', 'tag_ids',
        'smtp_relay_host', 'smtp_relay_port', 'smtp_relay_security',
        'smtp_relay_user', 'smtp_relay_password',
        'odoo_memory_limit', 'odoo_cpus', 'db_memory_limit', 'db_cpus',
        'backup_memory_limit', 'backup_cpus', 'smtp_memory_limit', 'smtp_cpus',
    }

    def _pre_auto_assign_host_hook(self, vals, safe):
        """Extension point for inheriting modules to inject host
        provisioning logic before auto-assign runs.

        Return ``None`` to let the default auto-assign logic run, or a
        response dict (e.g. ``{'blocked': True, 'message': ...}``) to
        abort early.
        """
        return None

    @http.route(['/cloud/create_instance'], type='jsonrpc', auth='user')
    def cloud_create_instance(self, vals):
        self._sec()._check_can_create_instance()
        repos = vals.pop('repos', None) if isinstance(vals, dict) else None
        domains = vals.pop('domains', None) if isinstance(vals, dict) else None
        safe = {k: v for k, v in vals.items() if k in self._CREATE_INSTANCE_ALLOWED}
        # If a single domain string was passed, convert to domain_ids
        domain_str = vals.get('domain', '').strip()
        if domain_str:
            safe['domain_ids'] = [(0, 0, {'hostname': domain_str})]
        elif domains:
            safe['domain_ids'] = [
                (0, 0, _domain_vals(d))
                for d in domains if (d.get('hostname') or '').strip()
            ]
        # ── Normalize odoo_version to string (frontend may send a number) ──
        if 'odoo_version' in safe:
            v = safe['odoo_version']
            if isinstance(v, (int, float)):
                safe['odoo_version'] = f"{float(v):.1f}"
        if 'tag_ids' in safe:
            safe['tag_ids'] = [fields.Command.set(safe['tag_ids'] or [])]
        # ── Inherit odoo_version and odoo_initial_lang from project ──────────
        project_id = safe.get('project_id')
        if project_id:
            project = request.env['cloud.project'].browse(project_id)
            if project.exists():
                if project.odoo_version:
                    safe['odoo_version'] = project.odoo_version
                if project.odoo_initial_lang and 'odoo_initial_lang' not in safe:
                    safe['odoo_initial_lang'] = project.odoo_initial_lang.id
        # ── Block if project has unresolved pip conflicts ──────────────────
        if project_id:
            pip_alert = request.env['cloud.alert'].search([
                ('code', '=', 'pip_conflict'),
                ('project_id', '=', project_id),
                ('state', '=', 'active'),
            ], limit=1)
            if pip_alert:
                return {
                    'blocked': True,
                    'reason': 'pip_conflict',
                    'message': _(
                        'Project has unresolved pip dependency conflicts. '
                        'Resolve them in the project settings before '
                        'creating an instance.'
                    ),
                }
        # Hook for inheriting modules to inject a host before auto-assign
        # runs. Core knows nothing about external VPS providers — that
        # logic belongs to the modules that extend this controller.
        hook_result = self._pre_auto_assign_host_hook(vals, safe)
        if hook_result is not None:
            return hook_result

        # ── Auto-assign host when not explicitly provided ─────────────────
        if not safe.get('host_id'):
            autoassign = (
                request.env['ir.config_parameter'].sudo()
                .get_param('incubacloud.host_autoassign', '0') == '1'
            )
            if not autoassign:
                return {
                    'blocked': True,
                    'reason': 'host_required',
                    'message': _(
                        'Please select a host for the instance.'
                    ),
                }
            cpus, ram = (
                request.env['cloud.instance']
                ._compute_instance_resources(safe)
            )
            best_host = request.env['cloud.host'].select_best_host(cpus, ram)
            if not best_host:
                return {
                    'blocked': True,
                    'reason': 'no_host',
                    'message': _(
                        'No host with sufficient resources is available.'
                    ),
                }
            safe['host_id'] = best_host.id
        Instance = request.env['cloud.instance']
        if repos:
            Instance = Instance.with_context(skip_project_repos=True)
        instance = Instance.create(safe)
        if repos:
            # skip_apply_requirements: the frontend already merged requirements
            # via _fetchAndMergeRequirements on branch change; re-fetching here
            # would block the request with N synchronous GitHub API calls.
            Repo = request.env['cloud.instance.repo'].with_context(
                skip_apply_requirements=True,
            )
            for seq, repo in enumerate(repos, start=10):
                if (repo.get('url') or '').strip():
                    Repo.create({
                        'instance_id': instance.id,
                        'sequence': seq,
                        'url': repo['url'].strip(),
                        'branch': (
                            (repo.get('branch') or 'main').strip() or 'main'
                        ),
                        'addons': repo.get('addons') or '',
                        'excludes': repo.get('excludes') or '',
                        'commit_sha': repo.get('commit_sha') or '',
                    })
        return {'id': instance.id, 'name': instance.name}

    # ── General settings ──────────────────────────────────────────────────

    @http.route(['/cloud/get_general_settings'], type='jsonrpc', auth='user')
    def cloud_get_general_settings(self):
        # Manager-gated, matching save_general_settings. The reads below
        # use sudo, so without this any logged-in user could see them.
        self._sec()._check_can_manage_hosts()
        ICP = request.env['ir.config_parameter'].sudo()
        bb_id = int(ICP.get_param(
            'incubacloud.backup_backend_id', 0,
        ) or 0)
        Settings = request.env['cloud.settings'].sudo()
        settings = Settings._get()
        return {
            'autoassign_enabled': ICP.get_param(
                'incubacloud.host_autoassign', '0',
            ) == '1',
            'default_backup_backend_id': bb_id or None,
            'audit_log_retention_days': int(
                ICP.get_param('incubacloud.audit_log_retention_days', '90') or 90
            ),
            'job_log_retention_days': settings.job_log_retention_days or 0,
            'job_retention_days': settings.job_retention_days or 0,
            'default_backup_alert_threshold_pct': (
                settings.default_backup_alert_threshold_pct or 0
            ),
            'github_event_retention_days': (
                settings.github_event_retention_days or 0
            ),
            'github_event_truncate_days': (
                settings.github_event_truncate_days or 0
            ),
            # ── Container log rotation ─────────────────────────────────
            'container_log_max_size': settings.container_log_max_size or '',
            'container_log_max_file': settings.container_log_max_file or 0,
            'odoo_log_archive_days': settings.odoo_log_archive_days or 0,
            'log_download_max_mb': settings.log_download_max_mb or 0,
            'log_search_max_files': settings.log_search_max_files or 0,
            'log_search_timeout_s': settings.log_search_timeout_s or 0,
            # ── Observability ──────────────────────────────────────────
            # The remote-write token is write-only, like the GitHub PAT:
            # it is a fleet-wide write credential, so the browser only
            # learns whether one is set, never its value.
            'metrics_enabled': bool(settings.metrics_enabled),
            'metrics_central_url': settings.metrics_central_url or '',
            'metrics_remote_write_url': settings.metrics_remote_write_url or '',
            'has_metrics_remote_write_token': bool(
                settings.metrics_remote_write_token
            ),
            'metrics_retention_days': settings.metrics_retention_days or 0,
            'grafana_base_url': settings.grafana_base_url or '',
            # ── Edge ───────────────────────────────────────────────────
            # The override plus what actually applies and where it comes
            # from, because the field alone says nothing about the list
            # in force when a layer above supplies one.
            'trusted_proxy_ranges': settings.trusted_proxy_ranges or '',
            'effective_trusted_proxy_ranges': Settings
            ._effective_trusted_proxy_ranges(),
            'trusted_proxy_source': Settings._trusted_proxy_source(),
            'github_webhook_allowlist': bool(settings.github_webhook_allowlist),
            'panel_host_id': settings.panel_host_id.id or None,
            'panel_hostname': settings.panel_hostname or '',
            'panel_service_url': settings.panel_service_url or '',
            'panel_tls_domain': settings.panel_tls_domain or '',
            # Derived when a layer above knows the answer; the client
            # renders those read-only rather than inviting an edit that
            # the next pass would overwrite.
            'panel_route': Settings._github_panel_route(),
            'panel_route_source': Settings._panel_route_source(),
            'panel_route_host_id': (
                Settings._github_panel_host().id or None
            ),
        }

    @http.route(['/cloud/save_general_settings'], type='jsonrpc', auth='user')
    def cloud_save_general_settings(
        self, autoassign_enabled=False, default_backup_backend_id=None,
        audit_log_retention_days=90, job_log_retention_days=30,
        job_retention_days=180,
        default_backup_alert_threshold_pct=80,
        github_event_retention_days=90, github_event_truncate_days=7,
        metrics_enabled=None, metrics_central_url=None,
        metrics_remote_write_url=None, metrics_remote_write_token=None,
        metrics_retention_days=None, grafana_base_url=None,
        container_log_max_size=None, container_log_max_file=None,
        odoo_log_archive_days=None, log_download_max_mb=None,
        log_search_max_files=None, log_search_timeout_s=None,
        trusted_proxy_ranges=None, github_webhook_allowlist=None,
        panel_host_id=None, panel_hostname=None, panel_service_url=None,
        panel_tls_domain=None,
    ):
        self._sec()._check_can_manage_hosts()
        # Coerce numeric inputs through try/except so a non-numeric
        # value reaches the user as a friendly error instead of
        # surfacing a ValueError stack trace through Odoo's default
        # JSON-RPC handler.
        def _safe_int(value, default=0):
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        backend_id = _safe_int(default_backup_backend_id, 0)
        if backend_id and not request.env['cloud.backup.backend'].sudo().browse(
            backend_id,
        ).exists():
            return {'ok': False, 'error': _('Unknown backup destination.')}
        ICP = request.env['ir.config_parameter'].sudo()
        ICP.set_param(
            'incubacloud.host_autoassign',
            '1' if autoassign_enabled else '0',
        )
        ICP.set_param(
            'incubacloud.backup_backend_id',
            str(backend_id) if backend_id else '0',
        )
        ICP.set_param(
            'incubacloud.audit_log_retention_days',
            str(max(0, _safe_int(audit_log_retention_days, 90))),
        )
        # Clamp to 0–100; 0 falls through to "no alerts by default" in the
        # backend's threshold-resolution logic so it's a safe lower bound.
        threshold = max(0, min(100, _safe_int(
            default_backup_alert_threshold_pct, 80,
        )))
        request.env['cloud.settings'].sudo()._get().write({
            'job_log_retention_days': max(
                0, _safe_int(job_log_retention_days, 30),
            ),
            'job_retention_days': max(
                0, _safe_int(job_retention_days, 180),
            ),
            'default_backup_alert_threshold_pct': threshold,
            'github_event_retention_days': max(
                0, _safe_int(github_event_retention_days, 90),
            ),
            'github_event_truncate_days': max(
                0, _safe_int(github_event_truncate_days, 7),
            ),
        })

        # ── Edge ──────────────────────────────────────────────────────
        # Written only when the client sent them, so a caller that
        # predates these knobs cannot blank them out. The range list goes
        # through the model constraint on purpose: a typo there narrows
        # who we believe without saying so, and the caller is told which
        # entries were rejected instead of having them dropped.
        edge_vals = {}
        if trusted_proxy_ranges is not None:
            edge_vals['trusted_proxy_ranges'] = str(
                trusted_proxy_ranges or '',
            ).strip()
        if github_webhook_allowlist is not None:
            edge_vals['github_webhook_allowlist'] = bool(
                github_webhook_allowlist,
            )
        for name, value in (
            ('panel_hostname', panel_hostname),
            ('panel_service_url', panel_service_url),
            ('panel_tls_domain', panel_tls_domain),
        ):
            if value is not None:
                edge_vals[name] = str(value or '').strip()
        if panel_host_id is not None:
            host_id = _safe_int(panel_host_id, 0)
            if host_id and not request.env['cloud.host'].sudo().browse(
                host_id,
            ).exists():
                return {'ok': False, 'error': _('Unknown host.')}
            edge_vals['panel_host_id'] = host_id or False
        if edge_vals:
            try:
                request.env['cloud.settings'].sudo()._get().write(edge_vals)
            except ValidationError as exc:
                return {'ok': False, 'error': exc.args[0] if exc.args else str(exc)}

        # ── Container log rotation ────────────────────────────────────
        # Written only when the client sent them, so a caller that
        # predates the knobs cannot blank them out. The size is
        # normalised to the one spelling the model accepts; anything
        # else is left to the model constraint, whose message names the
        # expected format.
        log_vals = {}
        if container_log_max_size is not None:
            log_vals['container_log_max_size'] = (
                str(container_log_max_size or '').strip().lower()
            )
        if container_log_max_file is not None:
            log_vals['container_log_max_file'] = _safe_int(
                container_log_max_file, CONTAINER_LOG_MAX_FILE_DEFAULT,
            )
        if odoo_log_archive_days is not None:
            log_vals['odoo_log_archive_days'] = _safe_int(
                odoo_log_archive_days, ODOO_LOG_ARCHIVE_DAYS_DEFAULT,
            )
        for field, value, default in (
            ('log_download_max_mb', log_download_max_mb,
             LOG_DOWNLOAD_MAX_MB_DEFAULT),
            ('log_search_max_files', log_search_max_files,
             LOG_SEARCH_MAX_FILES_DEFAULT),
            ('log_search_timeout_s', log_search_timeout_s,
             LOG_SEARCH_TIMEOUT_S_DEFAULT),
        ):
            if value is not None:
                log_vals[field] = _safe_int(value, default)
        if log_vals:
            request.env['cloud.settings'].sudo()._get().write(log_vals)

        # ── Observability ─────────────────────────────────────────────
        # Each field is written only when the client actually sent it, so
        # a caller that predates these settings cannot blank them out.
        metrics_vals = {}
        if metrics_enabled is not None:
            metrics_vals['metrics_enabled'] = bool(metrics_enabled)
        for field, value in (
            ('metrics_central_url', metrics_central_url),
            ('metrics_remote_write_url', metrics_remote_write_url),
            ('grafana_base_url', grafana_base_url),
        ):
            if value is not None:
                metrics_vals[field] = (value or '').strip()
        if metrics_retention_days is not None:
            metrics_vals['metrics_retention_days'] = max(
                1, _safe_int(metrics_retention_days, 90),
            )
        # Write-only secret: an empty string means "leave it alone", which
        # is what the form sends back when the operator did not retype it.
        if (metrics_remote_write_token or '').strip():
            metrics_vals['metrics_remote_write_token'] = (
                metrics_remote_write_token.strip()
            )
        if metrics_vals:
            request.env['cloud.settings'].sudo()._get().write(metrics_vals)

        return {'ok': True}

    @http.route(['/cloud/monitoring/deploy_central'], type='jsonrpc',
                auth='user')
    def cloud_monitoring_deploy_central(self, host_id):
        """Queue the metrics central deployment against *host_id*.

        Lives in Settings rather than on every host page on purpose: the
        central is one per platform, and an action offered from each host
        invites deploying several by accident.
        """
        self._sec()._check_can_manage_hosts()
        host = request.env['cloud.host'].browse(int(host_id or 0))
        if not host.exists():
            return {'ok': False, 'error': _('Host not found')}
        try:
            job_id = request.env['cloud.job'].sudo().enqueue(
                host.id, False, 'deploy_metrics_central',
            )
        except Exception as exc:
            return safe_error_response(
                exc, _("Failed to queue the central deployment"),
            )
        return {'ok': True, 'job_id': job_id}

    # ── Core rate-limit settings ──────────────────────────────────────────

    @http.route(['/cloud/get_core_rate_limits'], type='jsonrpc', auth='user')
    def cloud_get_core_rate_limits(self):
        """Return the configured caps for the core-owned rate limits.

        Mirrored on the Rates tab in Settings. Units are encoded in each key.
        """
        self._sec()._check_can_manage_hosts()
        s = request.env['cloud.settings'].sudo()._get()
        return {
            'rate_limit_webhook_per_min': s.rate_limit_webhook_per_min or 0,
            'rate_limit_terminal_per_min': s.rate_limit_terminal_per_min or 0,
            'rate_limit_terminal_user_per_min': (
                s.rate_limit_terminal_user_per_min or 0
            ),
            'rate_limit_connect_per_min': s.rate_limit_connect_per_min or 0,
            'rate_limit_connect_user_per_min': (
                s.rate_limit_connect_user_per_min or 0
            ),
            'rate_limit_logs_per_min': s.rate_limit_logs_per_min or 0,
            'rate_limit_log_search_per_min': (
                s.rate_limit_log_search_per_min or 0
            ),
            'rate_limit_github_previews_per_hour': (
                s.rate_limit_github_previews_per_hour or 0
            ),
            'rate_limit_github_imports_per_hour': (
                s.rate_limit_github_imports_per_hour or 0
            ),
        }

    @http.route(['/cloud/save_core_rate_limits'], type='jsonrpc', auth='user')
    def cloud_save_core_rate_limits(self, vals):
        """Persist the core rate-limit caps. Any non-positive value is
        stored as 0 and the model treats 0 as "use documented default"
        so a misconfiguration can't accidentally lock everyone out.
        """
        self._sec()._check_can_manage_hosts()
        allowed = {
            'rate_limit_webhook_per_min',
            'rate_limit_terminal_per_min',
            'rate_limit_terminal_user_per_min',
            'rate_limit_connect_per_min',
            'rate_limit_connect_user_per_min',
            'rate_limit_logs_per_min',
            'rate_limit_log_search_per_min',
            'rate_limit_github_previews_per_hour',
            'rate_limit_github_imports_per_hour',
        }
        safe = {
            k: max(0, int(v or 0))
            for k, v in (vals or {}).items() if k in allowed
        }
        request.env['cloud.settings'].sudo()._get().write(safe)
        return {'ok': True}

    @http.route(['/cloud/get_langs'], type='jsonrpc', auth='user')
    def cloud_get_langs(self):
        langs = request.env['res.lang'].with_context(active_test=False).search(
            [], order='name asc'
        )
        return [{'id': l.id, 'code': l.code, 'name': l.name} for l in langs]

    def _serialize_instance(self, inst):
        """Serialize a cloud.instance to a dict (shared by get_instance and get_project_full)."""
        Job = request.env['cloud.job']
        last_deploy = Job.search([
            ('instance_id', '=', inst.id),
            ('job_type_id.code', 'in',
             ('deploy_instance', 'rebuild_instance')),
            ('state', 'in', ('done', 'failed')),
        ], order='id desc', limit=1)
        timeline = Job._get_instance_timeline(inst.id, max_visible=5)
        jobs_total = timeline['total']
        # SSH endpoint (ip/user/port) is developer-gated at the ORM layer
        # (same gate as the host credential) — redact it below that role.
        # Reading it directly here would AccessError for a consultant; the
        # guard keeps this serializer usable by project-member stakeholders
        # while a Developer still gets the real endpoint (their restore
        # dialog builds an rsync command from it).
        is_developer = self._sec()._has_cloud_group('group_cloud_developer')
        return {
            'id': inst.id,
            'name': inst.name,
            'environment': inst.environment,
            'status': inst.status,
            'state': inst.state,
            'deployed': inst.deployed,
            'running': inst.running,
            'service_states': inst.service_states or {},
            'stop_is_expected': inst.stop_is_expected,
            'auto_rebuild': inst.auto_rebuild,
            'auto_update': inst.auto_update,
            'pending_pushes': [
                {
                    'id': p.id,
                    'push_repo': p.push_repo or '',
                    'push_branch': p.push_branch or '',
                    'push_sha': p.push_sha or '',
                    'push_message': p.push_message or '',
                    'push_by': p.push_by or '',
                    'skip_reason': p.skip_reason or '',
                    'queued_at': p.create_date,
                }
                for p in inst.pending_push_ids
            ],
            'tags': [
                {'id': t.id, 'name': t.name, 'color': t.color}
                for t in inst.tag_ids
            ],
            'all_tags': [
                {'id': t.id, 'name': t.name, 'color': t.color}
                for t in request.env['cloud.instance.tag'].search(
                    [], limit=_LIST_MAX, order='name',
                )
            ],
            'host_id': inst.host_id.id if inst.host_id else None,
            'host': inst.host_id.name if inst.host_id else '',
            'host_ip': (
                inst.host_id.ip_address
                if (inst.host_id and is_developer) else ''
            ),
            'host_user': (
                inst.host_id.user if (inst.host_id and is_developer) else ''
            ),
            'host_port': (
                inst.host_id.port if (inst.host_id and is_developer) else 22
            ),
            'move_origin_host_id': (
                inst.move_origin_host_id.id
                if inst.move_origin_host_id else None
            ),
            'move_origin_host': (
                inst.move_origin_host_id.name
                if inst.move_origin_host_id else ''
            ),
            'move_target_host_id': (
                inst.move_target_host_id.id
                if inst.move_target_host_id else None
            ),
            'move_target_host': (
                inst.move_target_host_id.name
                if inst.move_target_host_id else ''
            ),
            'move_rollback_in_progress': inst.move_rollback_in_progress,
            'odoo_version': inst.odoo_version,
            'odoo_commit_sha': inst.odoo_commit_sha or '',
            'last_deploy_date': last_deploy.create_date if last_deploy else None,
            'last_deploy_state': last_deploy.state if last_deploy else None,
            'config_dirty': inst.config_dirty,
            'odoo_initial_lang': inst.odoo_initial_lang.id if inst.odoo_initial_lang else None,
            'has_odoo_admin_password':
                _has_encrypted(inst, 'odoo_admin_password'),
            'odoo_proxy': inst.odoo_proxy or 'traefik',
            'postgres_version': inst.postgres_version or '17',
            'postgres_dbname': inst.postgres_dbname or '',
            'postgres_username': inst.postgres_username or '',
            'has_postgres_password':
                _has_encrypted(inst, 'postgres_password'),
            'domain': inst.domain or '',
            'smtp_relay_host': inst.smtp_relay_host or '',
            'smtp_relay_port': inst.smtp_relay_port or 587,
            'smtp_relay_security': inst.smtp_relay_security or 'starttls',
            'smtp_relay_user': inst.smtp_relay_user or '',
            'has_smtp_relay_password':
                _has_encrypted(inst, 'smtp_relay_password'),
            'odoo_conf': inst.odoo_conf or '',
            'odoo_memory_limit': inst.odoo_memory_limit or '',
            'odoo_cpus': inst.odoo_cpus or 0,
            'db_memory_limit': inst.db_memory_limit or '',
            'db_cpus': inst.db_cpus or 0,
            'backup_memory_limit': inst.backup_memory_limit or '',
            'backup_cpus': inst.backup_cpus or 0,
            'smtp_memory_limit': inst.smtp_memory_limit or '',
            'smtp_cpus': inst.smtp_cpus or 0,
            'pip_dependencies': inst.pip_dependencies or '',
            'apt_dependencies': inst.apt_dependencies or '',
            'compose_services': (inst.compose_services or 'odoo,db').split(','),
            'backup_backend_id': (
                inst.backup_backend_id.id if inst.backup_backend_id else None
            ),
            'effective_backup_backend_id': (
                inst.effective_backup_backend.id
                if inst.effective_backup_backend else None
            ),
            'effective_backup_backend_name': (
                inst.effective_backup_backend.name
                if inst.effective_backup_backend else ''
            ),
            'domains': [
                {
                    'id': d.id,
                    'hostname': d.hostname or '',
                    'redirect_to': d.redirect_to or '',
                    'cert_resolver': d.cert_resolver or 'letsencrypt',
                    'redirect_permanent': d.redirect_permanent,
                }
                for d in inst.domain_ids
            ],
            'repos': [
                {
                    'id': r.id,
                    'url': r.url or '',
                    'branch': r.branch or 'main',
                    'addons': r.addons or '',
                    'excludes': r.excludes or '',
                    'commit_sha': r.commit_sha or '',
                }
                for r in inst.repo_ids
            ],
            'activeJobs': timeline['active'],
            'recentJobs': timeline['recent'],
            'jobsTotal': jobs_total,
            'custom_actions': [
                {
                    'code': jt.code,
                    'name': jt.name,
                    'action_icon': jt.action_icon or 'fa-cog',
                    'action_confirm': jt.action_confirm or '',
                }
                for jt in request.env['cloud.job.type'].search([
                    ('show_as_action', '=', True),
                    ('apply_to', '=', 'instance'),
                ], order='action_order, id')
            ],
        }

    @http.route(['/cloud/get_instance'], type='jsonrpc', auth='user')
    def cloud_get_instance(self, instance_id):
        inst = request.env['cloud.instance'].browse(instance_id)
        if not inst.exists():
            return {'ok': False, 'error': _('Instance not found')}
        return self._serialize_instance(inst)

    @http.route(['/cloud/get_project_full'], type='jsonrpc', auth='user')
    def cloud_get_project_full(self, project_id):
        """Load entire project data in one RPC for instant switching."""
        project = request.env['cloud.project'].browse(project_id)
        if not project.exists():
            return {'ok': False, 'error': _('Project not found')}
        is_manager = self._sec()._has_cloud_group('group_cloud_manager')
        instances = {}
        for inst in project.instance_ids:
            instances[inst.id] = self._serialize_instance(inst)
        hosts = request.env['cloud.host'].search([], limit=_LIST_MAX, order='name')
        backends = request.env['cloud.backup.backend'].search(
            [], limit=_LIST_MAX, order='name',
        )
        return {
            'project': {
                'id': project.id,
                'name': project.name,
                'odoo_version': project.odoo_version or '19.0',
            },
            'instances': instances,
            'hosts': [{
                'id': h.id, 'name': h.name,
                'status': h.status,
                'traefik_deployed': h.traefik_deployed,
                'available_cpus': round(h.available_cpus, 2),
                'available_ram_gb': round(h.available_ram_gb, 2),
                'cpu_cores': h.cpu_cores,
                'ram_total_gb': h.ram_total_gb,
            } for h in hosts],
            'backup_backends': [{
                'id': b.id, 'name': b.name,
                # backup_dst embeds the bucket path — manager-only, like
                # the SSH endpoint above. Non-managers still get id/name so
                # the instance form can label the effective backend.
                'backup_dst': (b.backup_dst or '') if is_manager else '',
            } for b in backends],
        }

    _SAVE_INSTANCE_ALLOWED = {
        'name', 'environment', 'host_id',
        'odoo_version', 'odoo_commit_sha',
        'odoo_initial_lang', 'odoo_admin_password',
        'odoo_proxy',
        'postgres_version', 'postgres_dbname', 'postgres_username',
        'postgres_password',
        'smtp_relay_host', 'smtp_relay_port', 'smtp_relay_security',
        'smtp_relay_user', 'smtp_relay_password',
        'odoo_conf', 'pip_dependencies', 'apt_dependencies',
        'backup_backend_id', 'auto_rebuild', 'auto_update', 'tag_ids',
        'odoo_memory_limit', 'odoo_cpus',
        'db_memory_limit', 'db_cpus',
        'backup_memory_limit', 'backup_cpus',
        'smtp_memory_limit', 'smtp_cpus',
    }

    @http.route(['/cloud/save_instance'], type='jsonrpc', auth='user')
    def cloud_save_instance(self, instance_id, vals):
        self._sec()._check_cloud_group('group_cloud_consultant')
        inst = request.env['cloud.instance'].browse(instance_id)
        if not inst.exists():
            return {'ok': False, 'error': _('Instance not found')}
        repos = vals.pop('repos', None)
        domains = vals.pop('domains', None)
        safe = {
            k: v for k, v in vals.items()
            if k in self._SAVE_INSTANCE_ALLOWED
        }
        if 'odoo_version' in safe:
            v = safe['odoo_version']
            if isinstance(v, (int, float)):
                safe['odoo_version'] = f"{float(v):.1f}"
        if 'tag_ids' in safe:
            safe['tag_ids'] = [fields.Command.set(safe['tag_ids'] or [])]
        # Track whether host_id is changing (auto-domain may fire in write)
        host_changed = 'host_id' in safe and safe['host_id'] != (
            inst.host_id.id if inst.host_id else None
        )
        inst.write(safe)
        # Sync domains — skip if host just changed and frontend sent
        # empty domains, because write() auto-generated them.
        if domains is not None and not (
            host_changed and not domains and inst.domain_ids
        ):
            Domain = request.env['cloud.instance.domain']
            existing_ids = set(inst.domain_ids.ids)
            kept_ids = set()
            for d in domains:
                did = d.get('id')
                hostname = (d.get('hostname') or '').strip()
                if not hostname:
                    continue
                dvals = _domain_vals(d)
                if did and did in existing_ids:
                    Domain.browse(did).write(dvals)
                    kept_ids.add(did)
                else:
                    new = Domain.create({
                        **dvals, 'instance_id': inst.id,
                    })
                    kept_ids.add(new.id)
            to_delete = existing_ids - kept_ids
            if to_delete:
                Domain.browse(list(to_delete)).unlink()
        if repos is not None:
            # Skip GitHub fetches: pip_dependencies is already merged by the
            # frontend before saving (via /cloud/get_repo_requirements).
            Repo = request.env['cloud.instance.repo'].with_context(
                skip_apply_requirements=True,
            )
            existing_ids = set(inst.repo_ids.ids)
            kept_ids = set()
            for repo in repos:
                rid = repo.get('id')
                url = (repo.get('url') or '').strip()
                if not url:
                    continue
                branch = (repo.get('branch') or 'main').strip() or 'main'
                addons = (repo.get('addons') or '').strip()
                excludes = (repo.get('excludes') or '').strip()
                commit_sha = (repo.get('commit_sha') or '').strip()
                if rid and rid in existing_ids:
                    Repo.browse(rid).write({
                        'url': url,
                        'branch': branch,
                        'addons': addons,
                        'excludes': excludes,
                        'commit_sha': commit_sha,
                    })
                    kept_ids.add(rid)
                else:
                    Repo.create({
                        'instance_id': inst.id,
                        'url': url,
                        'branch': branch,
                        'addons': addons,
                        'excludes': excludes,
                        'commit_sha': commit_sha,
                    })
            to_unlink = existing_ids - kept_ids
            if to_unlink:
                Repo.browse(list(to_unlink)).unlink()
        return {'ok': True}
