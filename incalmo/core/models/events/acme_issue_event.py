from incalmo.core.models.events import Event


class ACMEIssueEvent(Event):
    """Observable result of a high-level ACME certificate request."""

    def __init__(
        self,
        host,
        agent,
        domain: str,
        directory_url: str,
        *,
        success: bool = False,
        cert_path: str | None = None,
        key_path: str | None = None,
        chain_path: str | None = None,
        fullchain_path: str | None = None,
        serial: str | None = None,
        issuer: str | None = None,
        sans: list[str] | None = None,
        not_before: str | None = None,
        not_after: str | None = None,
        error: str | None = None,
        output: str = "",
    ):
        self.host = host
        self.agent = agent
        self.domain = domain
        self.directory_url = directory_url
        self.success = success
        self.cert_path = cert_path
        self.key_path = key_path
        self.chain_path = chain_path
        self.fullchain_path = fullchain_path
        self.serial = serial
        self.issuer = issuer
        self.sans = list(sans or [])
        self.not_before = not_before
        self.not_after = not_after
        self.error = error
        self.output = output

    def __str__(self) -> str:
        host = getattr(self.host, "hostname", None) or getattr(
            self.host, "ip_addresses", []
        )
        fields = [
            f"ACMEIssueEvent: {'success' if self.success else 'failed'}",
            f"host={host}",
            f"agent={getattr(self.agent, 'paw', '')}",
            f"user={getattr(self.agent, 'username', '')}",
            f"domain={self.domain}",
            f"directory={self.directory_url}",
        ]
        if self.cert_path:
            fields.append(f"cert={self.cert_path}")
        if self.key_path:
            fields.append(f"key={self.key_path}")
        if self.chain_path:
            fields.append(f"chain={self.chain_path}")
        if self.fullchain_path:
            fields.append(f"fullchain={self.fullchain_path}")
        if self.serial:
            fields.append(f"serial={self.serial}")
        if self.issuer:
            fields.append(f"issuer={self.issuer}")
        if self.sans:
            fields.append("sans=" + ",".join(self.sans))
        if self.not_before:
            fields.append(f"not_before={self.not_before}")
        if self.not_after:
            fields.append(f"not_after={self.not_after}")
        if self.error:
            fields.append(f"error={self.error}")
        fields.append("output:")
        fields.append(self.output or "(no output)")
        return "\n".join(fields)
