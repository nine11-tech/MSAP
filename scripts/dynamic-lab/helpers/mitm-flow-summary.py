"""Bounded summary addon for the fixed MSAP example.com proxy smoke flows."""


class BoundedFlowSummary:
    def __init__(self):
        self.flow_count = 0
        self.matching_flow_count = 0

    def response(self, flow):
        request = flow.request
        if request.pretty_host != "example.com":
            return
        self.flow_count += 1
        if request.query.get("probe", "").startswith("msap-platform-smoke-"):
            self.matching_flow_count += 1

    def done(self):
        print(f"MSAP_FLOW_COUNT={self.flow_count}")
        print(f"MSAP_MATCHING_FLOW_COUNT={self.matching_flow_count}")


addons = [BoundedFlowSummary()]
