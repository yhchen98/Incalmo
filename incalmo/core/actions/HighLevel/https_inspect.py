from __future__ import annotations

import ipaddress
import posixpath
import re
import shlex

from ..high_level_action import HighLevelAction
from ..LowLevel import RunBashCommand
from incalmo.core.models.events import (
    BashOutputEvent,
    Event,
    HTTPSInspectionEvent,
)
from incalmo.core.models.network import Host
from incalmo.core.services import (
    AttackGraphService,
    EnvironmentStateService,
    LowLevelActionOrchestrator,
)
from incalmo.core.services.action_context import HighLevelContext


class HTTPSInspect(HighLevelAction):
    """Inspect an HTTPS endpoint's certificate and verification result through a host.

    This action performs a TLS handshake only; it does not send an HTTP request
    or credentials. ``server_name`` selects SNI; omitting it performs a
    no-SNI connection so a default certificate can be inspected. ``ca_file``
    selects the trust anchor used for verification; without it the host's
    default trust store is used.
    """

    def __init__(
        self,
        host: Host,
        target: str,
        port: int = 443,
        server_name: str | None = None,
        ca_file: str | None = None,
        timeout: int = 15,
    ):
        super().__init__()
        if not isinstance(host, Host):
            raise ValueError("host must be a compromised Host")
        if not isinstance(target, str) or not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", target
        ):
            try:
                target = str(ipaddress.IPv4Address(target))
            except (ValueError, TypeError):
                raise ValueError("target must be an IPv4 address or DNS name") from None
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("port must be an integer between 1 and 65535")
        if server_name is not None and (
            not isinstance(server_name, str)
            or not re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", server_name
            )
        ):
            raise ValueError("server_name must be a DNS name or None")
        if ca_file is not None and (
            not isinstance(ca_file, str)
            or not ca_file
            or not posixpath.isabs(ca_file)
            or "\x00" in ca_file
            or "\n" in ca_file
            or "\r" in ca_file
        ):
            raise ValueError("ca_file must be an absolute path or None")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 60:
            raise ValueError("timeout must be an integer between 1 and 60 seconds")
        self.host = host
        self.target = target
        self.port = port
        self.server_name = server_name
        self.ca_file = ca_file
        self.timeout = timeout

    def _command(self) -> str:
        args = [
            "openssl",
            "s_client",
            "-connect",
            f"{self.target}:{self.port}",
            "-showcerts",
            "-verify_return_error",
        ]
        if self.server_name is None:
            args.append("-noservername")
        else:
            args += ["-servername", self.server_name, "-verify_hostname", self.server_name]
        if self.ca_file is not None:
            args += ["-CAfile", self.ca_file]
        command = " ".join(shlex.quote(arg) for arg in args)
        return (
            "(\nset -u\n"
            "tmp=$(mktemp)\n"
            f"timeout {self.timeout} {command} </dev/null > \"$tmp\" 2>&1\n"
            "rc=$?\n"
            'echo "__HTTPS_RC:$rc"\n'
            'cat "$tmp"\n'
            "awk 'BEGIN{f=0} /^-----BEGIN CERTIFICATE-----/{f=1} "
            "f{print} /^-----END CERTIFICATE-----/{exit}' \"$tmp\" > \"$tmp.crt\" "
            "2>/dev/null || true\n"
            'echo "__HTTPS_CERT__"\n'
            'if [ -s "$tmp.crt" ]; then\n'
            '  openssl x509 -in "$tmp.crt" -noout -subject -issuer -serial '
            "-dates -ext subjectAltName 2>&1\n"
            "fi\n"
            "rm -f \"$tmp\" \"$tmp.crt\"\n"
            ")\n"
        )

    def _parse(self, raw: str) -> dict:
        rc_match = re.search(r"(?m)^__HTTPS_RC:(\d+)[ \t]*$", raw)
        verify = re.search(r"Verify return code: (\d+) \(([^)]*)\)", raw)
        protocol = re.search(r"(?m)^\s*Protocol\s*:\s*(\S+)", raw)
        subject = re.search(r"(?m)^subject=(.+)$", raw)
        issuer = re.search(r"(?m)^issuer=(.+)$", raw)
        serial = re.search(r"(?m)^serial=(.+)$", raw)
        before = re.search(r"(?m)^notBefore=(.+)$", raw)
        after = re.search(r"(?m)^notAfter=(.+)$", raw)
        sans = re.findall(r"DNS:([^\s,]+)", raw)
        verify_code = int(verify.group(1)) if verify else None
        certificate = {}
        if subject:
            certificate["subject"] = subject.group(1).strip()
        if issuer:
            certificate["issuer"] = issuer.group(1).strip()
        if serial:
            certificate["serial"] = serial.group(1).strip()
        if before:
            certificate["not_before"] = before.group(1).strip()
        if after:
            certificate["not_after"] = after.group(1).strip()
        if sans:
            certificate["sans"] = sorted(set(sans))
        connected = "CONNECTED" in raw or verify is not None
        return {
            "tls_connected": connected,
            "tls_valid": (verify_code == 0) if verify_code is not None else None,
            "tls_version": protocol.group(1) if protocol else None,
            "verify_code": verify_code,
            "verify_error": verify.group(2).strip() if verify else None,
            "certificate": certificate,
            "rc": int(rc_match.group(1)) if rc_match else None,
        }

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
        context: HighLevelContext,
    ) -> list[Event]:
        agents = sorted(
            (agent for agent in self.host.agents if agent is not None),
            key=lambda agent: (agent.username, agent.paw),
        )
        if not agents:
            raise RuntimeError(
                "HTTPS inspection requires a C2 agent on the compromised host"
            )
        agent = agents[0]
        attack_graph_service.record_action(self.host, self.host, "https_inspect")
        events = await low_level_action_orchestrator.run_action(
            RunBashCommand(agent, self._command(), timeout_seconds=30), context
        )
        raw = "\n".join(
            event.bash_output for event in events if isinstance(event, BashOutputEvent)
        )
        parsed = self._parse(raw)
        error = None
        if parsed["rc"] is None:
            error = "No complete TLS inspection result from C2; outcome unknown"
        elif not parsed["tls_connected"]:
            error = "TLS connection failed"
        elif not parsed["certificate"]:
            error = "TLS handshake completed but no certificate was returned"
        return [
            HTTPSInspectionEvent(
                self.host,
                agent,
                self.target,
                self.port,
                server_name=self.server_name,
                ca_file=self.ca_file,
                tls_connected=parsed["tls_connected"],
                tls_valid=parsed["tls_valid"],
                tls_version=parsed["tls_version"],
                verify_code=parsed["verify_code"],
                verify_error=parsed["verify_error"],
                certificate=parsed["certificate"],
                error=error,
                output=raw.strip(),
            )
        ]
