from __future__ import annotations

import ipaddress
import posixpath
import re
import shlex
import time
from urllib.parse import urlsplit

from ..high_level_action import HighLevelAction
from ..LowLevel import RunBashCommand
from incalmo.core.models.events import (
    ACMEIssueEvent,
    BashOutputEvent,
    Event,
)
from incalmo.core.models.network import Host
from incalmo.core.services import (
    AttackGraphService,
    EnvironmentStateService,
    LowLevelActionOrchestrator,
)
from incalmo.core.services.action_context import HighLevelContext
from incalmo.models.agent import Agent


class ACMEObtainCertificate(HighLevelAction):
    """Request a fresh HTTP-01 certificate from a caller-supplied ACME service.

    The action uses the installed certbot on the compromised host. The caller
    supplies the domain, ACME directory, and local trust-anchor path; no target
    values or certificate defaults are assumed. The certificate and key remain
    on the host and their paths are returned in the event.
    """

    def __init__(
        self,
        host: Host,
        domain: str,
        directory_url: str,
        trust_anchor: str,
        email: str,
        http01_port: int = 80,
        cert_name: str = "cert",
        bind_address: str | None = None,
        interface: str = "lo",
    ):
        super().__init__()
        if not isinstance(host, Host):
            raise ValueError("host must be a compromised Host")
        if not isinstance(domain, str) or not re.fullmatch(
            r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
            domain,
        ):
            raise ValueError("domain must be a DNS name")
        parsed = urlsplit(directory_url) if isinstance(directory_url, str) else None
        if (
            parsed is None
            or parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("directory_url must be an https URL without credentials or query")
        if not isinstance(trust_anchor, str) or not trust_anchor:
            raise ValueError("trust_anchor must be a nonempty path")
        if (
            not posixpath.isabs(trust_anchor)
            or "\x00" in trust_anchor
            or "\n" in trust_anchor
            or "\r" in trust_anchor
        ):
            raise ValueError("trust_anchor must be an absolute path")
        if not isinstance(email, str) or not re.fullmatch(r"[^@\s]+@[^@\s]+", email):
            raise ValueError("email must be a nonempty address")
        if isinstance(http01_port, bool) or not isinstance(http01_port, int) or not 1 <= http01_port <= 65535:
            raise ValueError("http01_port must be an integer between 1 and 65535")
        if not isinstance(cert_name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", cert_name):
            raise ValueError("cert_name must contain only letters, digits, dot, underscore, or hyphen")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", str(interface)):
            raise ValueError(f"invalid interface name: {interface!r}")
        if bind_address is not None:
            try:
                bind_address = str(ipaddress.IPv4Address(str(bind_address)))
            except ValueError as exc:
                raise ValueError("bind_address must be an IPv4 address") from exc
        self.host = host
        self.domain = domain
        self.directory_url = directory_url
        self.trust_anchor = trust_anchor
        self.email = email
        self.http01_port = http01_port
        self.cert_name = cert_name
        self.bind_address = bind_address
        self.interface = str(interface)

    def _agent(self) -> Agent:
        agents = sorted(
            (agent for agent in self.host.agents if agent is not None),
            key=lambda agent: (
                str(agent.privilege).lower() not in {"elevated", "root"},
                agent.username,
                agent.paw,
            ),
        )
        if not agents:
            raise RuntimeError(
                "ACME action requires a C2 agent on the compromised host "
                f"{self.host.hostname or self.host.ip_addresses}"
            )
        return agents[0]

    def _paths(self) -> dict[str, str]:
        base = f"/tmp/incalmo-acme-{self.cert_name}-{time.time_ns()}"
        config = base + "/config"
        live = config + "/live/" + self.cert_name
        return {
            "base": base,
            "config": config,
            "work": base + "/work",
            "logs": base + "/logs",
            "cert": live + "/cert.pem",
            "key": live + "/privkey.pem",
            "chain": live + "/chain.pem",
            "fullchain": live + "/fullchain.pem",
        }

    def _command(self) -> str:
        paths = self._paths()
        address = ""
        if self.bind_address is not None and self.bind_address != "0.0.0.0":
            address = (
                f'if ! ip -4 addr show | grep -Fq "inet {self.bind_address}/"; then '
                f"ip addr add {self.bind_address}/32 dev {shlex.quote(self.interface)}; fi\n"
            )
        certbot = (
            f"REQUESTS_CA_BUNDLE={shlex.quote(self.trust_anchor)} "
            "timeout 180 certbot certonly --standalone --non-interactive "
            "--agree-tos --no-eff-email --preferred-challenges http-01 "
            f"--http-01-port {self.http01_port} "
            f"--server {shlex.quote(self.directory_url)} "
            f"--email {shlex.quote(self.email)} "
            f"--domains {shlex.quote(self.domain)} "
            f"--cert-name {shlex.quote(self.cert_name)} "
            f"--config-dir {shlex.quote(paths['config'])} "
            f"--work-dir {shlex.quote(paths['work'])} "
            f"--logs-dir {shlex.quote(paths['logs'])}"
        )
        return (
            "(\nset -u\n"
            f"mkdir -p {shlex.quote(paths['base'])} {shlex.quote(paths['config'])} "
            f"{shlex.quote(paths['work'])} {shlex.quote(paths['logs'])}\n"
            + address
            + f"output=$({certbot} 2>&1)\n"
            "rc=$?\n"
            'printf \'%s\\n\' "$output"\n'
            f"if [ \"$rc\" -eq 0 ] && [ -s {shlex.quote(paths['cert'])} ] && "
            f"[ -s {shlex.quote(paths['key'])} ]; then\n"
            f"  echo __ACME_CERT:{paths['cert']}\n"
            f"  echo __ACME_KEY:{paths['key']}\n"
            f"  echo __ACME_CHAIN:{paths['chain']}\n"
            f"  echo __ACME_FULLCHAIN:{paths['fullchain']}\n"
            f"  openssl x509 -in {shlex.quote(paths['cert'])} "
            "-noout -serial -issuer -dates -ext subjectAltName 2>&1\n"
            "  echo __ACME_OK:1\n"
            "else\n"
            "  echo __ACME_OK:0\n"
            "fi\n"
            "echo __ACME_RC:$rc\n"
            ")\n"
        )

    async def _run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        agent: Agent,
        command: str,
        context: HighLevelContext,
    ) -> tuple[str, str, int | None]:
        events = await low_level_action_orchestrator.run_action(
            RunBashCommand(agent, command), context
        )
        raw = "\n".join(
            event.bash_output for event in events if isinstance(event, BashOutputEvent)
        )
        match = re.search(r"(?m)^__ACME_RC:(\d+)[ \t]*$", raw)
        rc = int(match.group(1)) if match else None
        cleaned = re.sub(r"(?m)^__ACME_(?:RC|CERT|KEY|CHAIN|FULLCHAIN|OK):.*\n?", "", raw).strip()
        return raw, cleaned, rc

    def _parse(self, raw: str) -> dict:
        cert = re.search(r"(?m)^__ACME_CERT:(.+)$", raw)
        key = re.search(r"(?m)^__ACME_KEY:(.+)$", raw)
        chain = re.search(r"(?m)^__ACME_CHAIN:(.+)$", raw)
        fullchain = re.search(r"(?m)^__ACME_FULLCHAIN:(.+)$", raw)
        serial = re.search(r"(?m)^serial=(.+)$", raw)
        issuer = re.search(r"(?m)^issuer=(.+)$", raw)
        before = re.search(r"(?m)^notBefore=(.+)$", raw)
        after = re.search(r"(?m)^notAfter=(.+)$", raw)
        sans = re.findall(r"DNS:([^\s,]+)", raw)
        return {
            "cert_path": cert.group(1).strip() if cert else None,
            "key_path": key.group(1).strip() if key else None,
            "chain_path": chain.group(1).strip() if chain else None,
            "fullchain_path": fullchain.group(1).strip() if fullchain else None,
            "serial": serial.group(1).strip() if serial else None,
            "issuer": issuer.group(1).strip() if issuer else None,
            "sans": sans,
            "not_before": before.group(1).strip() if before else None,
            "not_after": after.group(1).strip() if after else None,
        }

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
        context: HighLevelContext,
    ) -> list[Event]:
        agent = self._agent()
        attack_graph_service.record_action(
            self.host, self.host, "acme_obtain_certificate"
        )
        raw, cleaned, rc = await self._run(
            low_level_action_orchestrator, agent, self._command(), context
        )
        if rc != 0 or "__ACME_OK:1" not in raw:
            return [
                ACMEIssueEvent(
                    self.host,
                    agent,
                    self.domain,
                    self.directory_url,
                    success=False,
                    error="certificate request failed",
                    output=cleaned or raw,
                )
            ]
        parsed = self._parse(raw)
        return [
            ACMEIssueEvent(
                self.host,
                agent,
                self.domain,
                self.directory_url,
                success=True,
                output=cleaned,
                **parsed,
            )
        ]
