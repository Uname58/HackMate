"""Scope-bound browser adapter for Skill Eval cases."""


class ScopeBoundEvalCDP:
    """Expose only Eval browser operations, and gate every target navigation."""

    def __init__(self, cdp, scope_gate):
        if cdp is None or scope_gate is None:
            raise ValueError("CDP and an explicit Scope Gate are required")
        self._cdp = cdp
        self._gate = scope_gate

    def verify_xss(self, url, index=0, wait=4, autotrigger=True, test_tab=True):
        return self._cdp.verify_xss(
            url, index=index, wait=wait, autotrigger=autotrigger,
            test_tab=True, scope_gate=self._gate)

    def check_case(self, case, vuln=""):
        """Fail before Eval if a browser-backed case points outside the task scope."""
        urls = []
        verify_url = case.get("verify_url")
        if verify_url and "{payload}" in verify_url and (not vuln or vuln == "xss"):
            urls.append(verify_url)
        evidence = case.get("evidence")
        if isinstance(evidence, dict) and evidence.get("url") and "{payload}" in evidence["url"]:
            urls.append(evidence["url"])
        for template in urls:
            url = template.replace("{payload}", "HackMateEval")
            self._gate.check("TEST", url=url, method="GET", count=0)
            self._gate.check("OBSERVE", url=url, method="GET", count=0)

    def navigate(self, url, index=0, test_tab=True):
        return self._cdp.navigate(
            url, index=index, test_tab=True, scope_gate=self._gate, action="TEST")

    def read_page_text(self, tab=None, timeout=10, test_tab=True):
        target = self._cdp.ensure_test_tab().get("url")
        self._gate.check("OBSERVE", url=target, method="GET", count=0)
        return self._cdp.read_page_text(timeout=timeout, test_tab=True)
