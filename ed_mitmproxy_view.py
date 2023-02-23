from typing import Optional

from mitmproxy import contentviews
from mitmproxy import flow
from mitmproxy import http
from mitmproxy.contentviews.base import format_pairs
from mitmproxy.contentviews.xml_html import ViewXmlHtml
from mitmproxy.contentviews.json import ViewJSON

from urllib.parse import parse_qsl
from urllib.parse import urlparse

import edcrypt
import itertools


class ViewEliteDangerous(contentviews.View):
  name = "EliteDangerous"

  def __call__(
      self,
      data: bytes,
      *,
      content_type: Optional[str] = None,
      flow: Optional[flow.Flow] = None,
      http_message: Optional[http.Message] = None,
      **unknown_metadata,
  ) -> contentviews.TViewResult:
    decryptor = edcrypt.EDCrypt(edcrypt.EDCrypt.SALT["291.50.0.0"])
    query_header = iter([[("highlight", "= Query =========== ")]])
    data_header = iter([[("highlight", "= Data ============ ")]])

    url = getattr(http_message, "url", None)
    if url:
      query = urlparse(url).query
      nonce = bytes(http_message.headers["Nonce"], 'utf-8')
      query, post_data = decryptor.decode_request(nonce, bytes(query, 'utf-8'), data)
      query_plaintext = query.decode("utf-8")
      output_chain = itertools.chain(query_header, format_pairs(parse_qsl(query_plaintext)), data_header)
      if content_type and "application/json" in content_type:
        formatter = ViewJSON()
        output_chain = itertools.chain(output_chain, formatter(post_data)[1])
      elif content_type and 'application/xml' in content_type:
        # TODO
        output_chain = itertools.chain(output_chain, iter([[("codeeditor", post_data)]]))
      elif content_type and 'application/x-www-form-urlencoded' in content_type and not "journal" in url:
        output_chain = itertools.chain(output_chain, iter([[("codeeditor", post_data)]]))
      else:
        output_chain = itertools.chain(output_chain, iter([[("codeeditor", post_data)]]))
      return "EliteDangerous", output_chain

    status_code = getattr(http_message, "status_code", None)
    if status_code:
      nonce = bytes(http_message.headers["Nonce"], 'utf-8')
      decoded_data = decryptor.decode_response(nonce, data)
      output_chain = None
      if content_type and "application/json" in content_type:
        formatter = ViewJSON()
        output_chain = formatter(decoded_data)[1]
      elif content_type and 'application/xml' in content_type:
        formatter = ViewXmlHtml()
        output_chain = formatter(decoded_data)[1]
      else:
        output_chain = contentviews.format_text(decoded_data.decode("utf-8"))
      return "EliteDangerous", output_chain

  def render_priority(
      self,
      data: bytes,
      *,
      content_type: Optional[str] = None,
      flow: Optional[flow.Flow] = None,
      http_message: Optional[http.Message] = None,
      **unknown_metadata,
  ) -> float:
    if "Encrypted" in http_message.headers.keys() and http_message.headers["Encrypted"] == "1":
      return 5
    if "Content-Type" in http_message.headers.keys() and "encrypted=1" in http_message.headers["Content-Type"]:
      return 5
    return 0


view = ViewEliteDangerous()


def load(l):
  contentviews.add(view)


def done():
  contentviews.remove(view)
