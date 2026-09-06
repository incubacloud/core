"""Reaching the certificate store Traefik keeps for itself.

Traefik writes every certificate it obtains into a single JSON file and
publishes all of them under the default TLS store when it starts. The
handshake then picks by server name, before any router is consulted —
so a name whose router was changed to serve the host's own certificate
keeps being answered with the stored one, indefinitely, and the change
looks like it did nothing.

The file is not on the host: the compose file gives Traefik a named
volume for it, which only root can read from the filesystem. It is
reached through the running container instead, which is also what makes
the write safe — ``cat`` into the existing file keeps the ``0600`` mode
Traefik refuses to start without, where moving a new file over it would
not.
"""
import json

#: Label of the step that reads the store back once the proxy is up.
CONFIRM_LABEL = "Confirm the retired certificates are gone"

#: Where the store is mounted inside the proxy container.
STORE_PATH = "/etc/traefik/acme/acme.json"

#: Where the replacement is staged on the host before being fed in.
LOCAL_PATH = "/tmp/.incubacloud-acme.json"

_COMPOSE = (
    "cd ~/traefik && docker compose -p inverseproxy -f inverseproxy.yaml"
)

#: Print the store. Fails when the proxy is not running, which is the
#: honest answer: there is no store to speak of before the first start.
READ_COMMAND = f"{_COMPOSE} exec -T proxy cat {STORE_PATH}"

#: Replace the store, then drop the staged copy — it is a list of every
#: name this host serves, and there is no reason to leave it in ``/tmp``.
#: Written through the container's stdin rather than copied in, so the
#: file keeps the ownership and mode it already has: Traefik refuses a
#: store readable by anyone else and would then obtain nothing at all.
#: Chained rather than sequenced so a failed write is still a failed
#: step: the staged copy surviving is harmless, a silent success is not.
WRITE_COMMAND = (
    f"{_COMPOSE} exec -T proxy sh -c 'cat > {STORE_PATH}' < {LOCAL_PATH}"
    f" && rm -f {LOCAL_PATH}"
)


async def read(transport):
    """Return the host's certificate store, or ``None`` if unreadable.

    ``None`` and an empty store are different answers and both are
    normal: a host whose proxy is not running yet cannot be asked, while
    one that has never obtained a certificate has nothing to say. Only
    the second is safe to act on, so they are kept apart.

    :param transport: connected SSH transport
    :return: the store's contents, or ``None`` when it could not be read
    :rtype: str | None
    """
    result = await transport.run(READ_COMMAND)
    if result.exit_status != 0:
        return None
    return result.stdout or ""


class AcmeStorePruneMixin:
    """Retire stored certificates a host no longer serves from.

    For the two jobs that hand a host its own certificate and restart
    the proxy. Installing the certificate is only half the change: the
    proxy goes on serving what it obtained earlier, because those are
    chosen by server name before any router is consulted. This is the
    other half.

    Kept as a mixin rather than duplicated because the two jobs have to
    agree exactly — a host converging one way through a settings push
    and another through a full setup is the drift this replaces.
    """

    #: Names retired by this run. Decided in ``before_execute``, where
    #: the store can be read, and read back when commands are built.
    _acme_retired = ()

    async def _prepare_acme_prune(self, transport):
        """Return this host's store with the entries it no longer needs gone.

        Only asked of a host that has a certificate to serve instead:
        with nothing to fall back on, retiring an entry would leave the
        name answered by a throwaway.

        A store that cannot be read is reported and left alone. That is
        the state of a host whose proxy is not up — including the first
        run of a setup, where there is nothing to prune anyway.

        :param transport: connected SSH transport
        :return: the pruned store, or ``''`` when there is nothing to do
        :rtype: str
        """
        host = self.job.host_id
        cert, key = host._effective_tls_default()
        if not (cert and key):
            return ''
        stored = await read(transport)
        if stored is None:
            self._sys(
                '⚠ Could not read the certificate store — leaving it '
                'untouched. Any name already issued a certificate keeps '
                'being served that one.'
            )
            return ''
        pruned, retired = host._prune_acme_store(stored)
        if not retired:
            return ''
        self._acme_retired = tuple(retired)
        self._sys(
            f'✓ Retiring {len(retired)} stored certificate name(s) this '
            f'host now serves from its own: {", ".join(retired)}.'
        )
        return pruned

    def _acme_prune_step(self):
        """Return the command that retires them, or ``None``.

        Belongs immediately before the proxy is restarted, so it comes
        back having forgotten them. Traefik does not write the store
        back on shutdown, so the edit survives the restart — measured
        on 2.11.

        :rtype: tuple | None
        """
        if not self._acme_retired:
            return None
        return ('Retire stored certificates', WRITE_COMMAND)

    def _acme_confirm_step(self):
        """Return the command that reads the store back, or ``None``.

        Belongs *after* the proxy has been brought back, and exists
        because the write step cannot tell whether it worked: it reports
        the exit status of a redirection, which succeeds against a store
        that ends up truncated, and says nothing about the proxy having
        come back at all. Reading through the container answers both —
        a container that is not running cannot be read from.

        :rtype: tuple | None
        """
        if not self._acme_retired:
            return None
        return (CONFIRM_LABEL, READ_COMMAND)

    def _acme_prune_errors(self, results):
        """Return what the read-back says went wrong, if anything.

        Fails on anything short of proof, because the alternative is a
        job that reports success over a store nobody looked at. A name
        still present means the write did not take; an unreadable or
        unparseable store means the proxy did not come back, or came
        back over a file it cannot use — in which case it holds no
        certificates at all and answers every handshake with a
        throwaway.

        :param dict results: ``{label: {'stdout', 'exit_status'}}``
        :return: error strings, empty when the retirement is confirmed
        :rtype: list
        """
        if not self._acme_retired:
            return []
        outcome = results.get(CONFIRM_LABEL)
        if not outcome or outcome.get('exit_status') != 0:
            return [
                'Could not read the certificate store back after the '
                'restart, so the retirement is unconfirmed and the proxy '
                'may not have come back.',
            ]
        try:
            store = json.loads(outcome.get('stdout') or '')
        except (TypeError, ValueError):
            return [
                'The certificate store is unreadable after the restart. '
                'Traefik holds no certificates from an unparseable store '
                'and answers every handshake with a throwaway one.',
            ]
        left = set()
        for resolver in (store or {}).values():
            if not isinstance(resolver, dict):
                continue
            for entry in resolver.get('Certificates') or []:
                left.update(self.job.host_id._acme_entry_names(entry))
        survived = sorted(left & set(self._acme_retired))
        if survived:
            return [
                'Still in the certificate store after the restart: '
                f'{", ".join(survived)}. They keep being served instead '
                'of the certificate this host was given.',
            ]
        return []
