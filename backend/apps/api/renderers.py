import json

from rest_framework.renderers import BaseRenderer


class PDFRenderer(BaseRenderer):
    """Binary renderer for authenticated, on-demand PDF report downloads."""

    media_type = "application/pdf"
    format = "pdf"
    charset = None
    render_style = "binary"

    def render(self, data, accepted_media_type=None, renderer_context=None):
        if data is None:
            return b""
        if isinstance(data, bytes):
            return data
        if isinstance(data, bytearray):
            return bytes(data)
        return json.dumps(data, separators=(",", ":")).encode("utf-8")
