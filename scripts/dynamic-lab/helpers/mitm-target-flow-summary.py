"""Emit a bounded, body-free summary for MSAP target proxy captures."""

import json


MAX_FLOWS = 100
ALLOWED_HOSTS = {"owasp.org", "www.owasp.org"}


class TargetFlowSummary:
    def __init__(self):
        self.items = []

    def _record(self, flow, *, event):
        if len(self.items) >= MAX_FLOWS:
            return
        request = getattr(flow, "request", None)
        if request is None or request.pretty_host not in ALLOWED_HOSTS:
            return
        response = getattr(flow, "response", None)
        error = getattr(flow, "error", None)
        self.items.append({
            "event": event,
            "method": str(request.method or "")[:12],
            "scheme": str(request.scheme or "")[:12],
            "host": str(request.pretty_host or "")[:255],
            "path": str(request.path or "")[:500],
            "status_code": int(response.status_code) if response is not None else None,
            "tls_established": bool(str(request.scheme or "").lower() == "https" and response is not None),
            "error": str(getattr(error, "msg", "") or "")[:500],
        })

    def response(self, flow):
        self._record(flow, event="response")

    def error(self, flow):
        self._record(flow, event="error")

    def done(self):
        successful = sum(
            1 for item in self.items
            if item["tls_established"] and isinstance(item["status_code"], int)
            and 200 <= item["status_code"] < 400
        )
        print("MSAP_TARGET_FLOW_SUMMARY=" + json.dumps({
            "flow_count": len(self.items),
            "successful_tls_flow_count": successful,
            "flows": self.items,
            "truncated": len(self.items) >= MAX_FLOWS,
        }, separators=(",", ":")))


addons = [TargetFlowSummary()]
