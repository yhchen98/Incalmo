import json

from incalmo.core.models.events import Event


class HTTPSInspectionEvent(Event):
    """Observable TLS identity and verification result for one HTTPS endpoint."""

    def __init__(
        self,
        host,
        agent,
        target: str,
        port: int,
        *,
        server_name: str | None = None,
        ca_file: str | None = None,
        tls_connected: bool = False,
        tls_valid: bool | None = None,
        tls_version: str | None = None,
        verify_code: int | None = None,
        verify_error: str | None = None,
        certificate: dict | None = None,
        error: str | None = None,
        output: str = "",
    ):
        self.host = host
        self.agent = agent
        self.target = target
        self.port = port
        self.server_name = server_name
        self.ca_file = ca_file
        self.tls_connected = tls_connected
        self.tls_valid = tls_valid
        self.tls_version = tls_version
        self.verify_code = verify_code
        self.verify_error = verify_error
        self.certificate = certificate or {}
        self.error = error
        self.output = output

    def __str__(self) -> str:
        host = getattr(self.host, "hostname", None) or getattr(
            self.host, "ip_addresses", []
        )
        fields = [
            f"HTTPSInspectionEvent: {self.target}:{self.port}",
            f"host={host}",
            f"agent={getattr(self.agent, 'paw', '')}",
            f"connected={self.tls_connected}",
            f"valid={self.tls_valid}",
        ]
        if self.server_name:
            fields.append(f"server_name={self.server_name}")
        if self.tls_version:
            fields.append(f"tls_version={self.tls_version}")
        if self.verify_code is not None:
            fields.append(f"verify_code={self.verify_code}")
        if self.verify_error:
            fields.append(f"verify_error={self.verify_error}")
        if self.certificate:
            fields.append("certificate:")
            fields.append(json.dumps(self.certificate, indent=2))
        if self.error:
            fields.append(f"error={self.error}")
        fields.append("output:")
        fields.append(self.output or "(no output)")
        return "\n".join(fields)
