# Part of Odoo. See LICENSE file for full copyright and licensing details.
{
    "name": "Incubacloud",
    "version": "1.0.119",
    "summary": "Deploy, manage and monitor doodba-based Odoo instances via SSH",
    "sequence": 10,
    "description": """
IncubaCloud — Cloud Infrastructure Management
==============================================
Deploy, rebuild and monitor doodba-based Odoo instances on your own servers.
Safe rebuilds with boot tests, automatic module updates via click-odoo-update,
S3 backups, GitHub webhook integration, and a full OWL single-page application.
    """,
    "category": "Tools",
    "website": "https://www.incubacloud.io",
    "depends": [
        "base",
        "web",
        "bus",
        "queue_job",
    ],
    "data": [
        # Security loads first so groups and the cron bot user exist
        # before any cron record (which references ``user_id``) is
        # created by the data XMLs below.
        "security/cloud_security.xml",
        "security/ir.model.access.csv",
        "security/cloud_rules.xml",
        # Data
        "data/job_type.xml",
        "data/host_metrics_cron.xml",
        "data/observability_reconcile_cron.xml",
        "data/docker_prune_cron.xml",
        "data/instance_health_cron.xml",
        "data/backup_cleanup_cron.xml",
        "data/backup_list_cron.xml",
        "data/backup_measure_cron.xml",
        "data/retention_declared_cron.xml",
        "data/managed_backend_unused_cron.xml",
        "data/production_no_backup_cron.xml",
        "data/mail_template_backup_usage_alert.xml",
        "data/audit_log_purge_cron.xml",
        "data/rotate_secrets_cron.xml",
        "data/github_event_purge_cron.xml",
        "data/github_webhook_silence_cron.xml",
        "data/github_hook_ranges_cron.xml",
        "data/rate_limit_gc_cron.xml",
        "data/job_duration_cron.xml",
        "data/job_purge_cron.xml",
        "data/terminal_route_gc_cron.xml",
        "data/restore_staging_gc_cron.xml",
        "data/restore_upload_grant_gc_cron.xml",
        "data/archive_verify_cron.xml",
        "data/alert_gc_cron.xml",
        "data/metric_rule_data.xml",
        "data/instance_liveness_cron.xml",
        "data/mail_digest_templates.xml",
        "data/notification_digest_cron.xml",
        "data/traefik_templates.xml",
        "data/move_recovery_cron.xml",
        # Views
        "views/dashboard_action.xml",
        "views/menus.xml",
        "views/cloud_assets_index.xml",
        "views/log_terminal_page.xml",
        "views/github_setup_page.xml",
        "views/cloud_terminal_page.xml",
        "views/cloud_instance_logs.xml",
        "views/cloud_github_event.xml",
    ],
    "installable": True,
    "application": True,
    # Imported into the server process before any registry exists,
    # which is the only moment early enough to correct the visitor
    # address Odoo reads on the very first request.
    "post_load": "_post_load",
    "post_init_hook": "_post_init_hook",
    "assets": {
        # Assets
        "incubacloud.base_app": [
            ("include", "web._assets_helpers"),
            ("include", "web._assets_backend_helpers"),
            "web/static/src/scss/pre_variables.scss",
            "web/static/lib/bootstrap/scss/_variables.scss",
            "web/static/lib/bootstrap/scss/_variables-dark.scss",
            "web/static/lib/bootstrap/scss/_maps.scss",
            ("include", "web._assets_bootstrap_backend"),
            ("include", "web._assets_core"),
            ("remove", "web/static/src/core/browser/router.js"),
            ("remove", "web/static/src/core/debug/**/*"),
            "web/static/src/libs/fontawesome/css/font-awesome.css",
            "web/static/src/views/fields/formatters.js",
            "web/static/lib/odoo_ui_icons/*",
            "bus/static/src/services/bus_service.js",
            "bus/static/src/services/worker_service.js",
            "bus/static/src/bus_parameters_service.js",
            "bus/static/src/legacy_multi_tab_service.js",
            "bus/static/src/multi_tab_service.js",
            "bus/static/src/multi_tab_shared_worker_service.js",
            "bus/static/src/multi_tab_fallback_service.js",
            "bus/static/src/workers/*",
        ],
        "incubacloud._assets_cloud": [
            ("include", "incubacloud.base_app"),
            # Cloud files
            "incubacloud/static/src/scss/variables.scss",
            "incubacloud/static/src/scss/relay.scss",
            "incubacloud/static/src/scss/modal_chrome.scss",
            "incubacloud/static/src/utils/**/*",
            "incubacloud/static/src/toast/**/*",
            "incubacloud/static/src/store/**/*",
            "incubacloud/static/src/components/**/*",
            "incubacloud/static/src/app/*",
            ("remove", "incubacloud/static/src/app/main.js"),
        ],
        # Bundle that starts the cloud, loaded on /cloud
        "incubacloud.assets_prod": [
            ("include", "incubacloud._assets_cloud"),
            "incubacloud/static/src/app/main.js",
        ],
        # JS unit tests (Hoot framework)
        "web.assets_unit_tests": [
            "incubacloud/static/src/utils/**/*.js",
            "incubacloud/static/src/toast/**/*.js",
            "incubacloud/static/src/store/**/*.js",
            "incubacloud/static/src/components/**/*.js",
            "incubacloud/static/src/app/app.js",
            "incubacloud/static/tests/**/*.test.js",
        ],
    },
    "author": "IncubaCloud",
    "license": "Other proprietary",
}
