"""SHA-bound commit-status adapter; inert until independent owner admission.

No status call is made from the quarantined workflow. The controller must use
a separately scoped token for the source repository, never a guest credential.
No automatic retry after ambiguous network results.
"""
from __future__ import annotations
import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler
from marketing_vm_contract import SOURCE_REPO, STATUS_CONTEXT, SHA, prepare_status_payload

API = "https://api.github.com/repos/baum777/unitera_marketing_agent-team/statuses/"

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("status redirect denied")

def payload(receipt, issues, *, owner_approved=False, vm_qualified=False, writer_qualified=False):
    return prepare_status_payload(receipt, issues, owner_approved=owner_approved,
                                  vm_qualified=vm_qualified,
                                  status_writer_qualified=writer_qualified)

def send(candidate, token, *, post=None):
    if set(candidate) != {"repository", "sha", "context", "state", "description"}:
        raise ValueError("unknown status fields")
    if candidate["repository"] != SOURCE_REPO or candidate["context"] != STATUS_CONTEXT:
        raise ValueError("wrong status destination/context")
    if not isinstance(candidate["sha"], str) or not SHA.fullmatch(candidate["sha"]):
        raise ValueError("invalid source SHA")
    if candidate["state"] != "success":
        raise ValueError("only independently verified success may be reported")
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{20,256}", token):
        raise PermissionError("source commit-status credential unavailable")
    body = json.dumps({"state": "success", "context": STATUS_CONTEXT,
                       "description": candidate["description"][:140]},
                      separators=(",", ":")).encode()
    req = Request(API + candidate["sha"], data=body, method="POST",
                  headers={"Authorization": "Bearer " + token,
                           "Accept": "application/vnd.github+json",
                           "X-GitHub-Api-Version": "2022-11-28",
                           "Content-Type": "application/json"})
    try:
        with (post or build_opener(NoRedirect()).open)(req, timeout=20) as response:
            status = response.status
            response.read(1024)
    except HTTPError as exc:
        raise RuntimeError("status write rejected HTTP " + str(exc.code)) from None
    except (URLError, TimeoutError, OSError):
        raise RuntimeError("status outcome unknown; no automatic retry") from None
    if status != 201:
        raise RuntimeError("unexpected status response; independent readback required")
    return {"source_sha": candidate["sha"], "context": STATUS_CONTEXT,
            "provider_accepted": True, "independent_readback_required": True}


def readback(sha, token, *, get=None, expect_state="success"):
    """Independent GET readback after a status POST; binds exact SHA and context.

    Uses a separate request path from the write. A missing context, a different
    target SHA or a state other than the expected one is a hard failure; an
    ambiguous network result stays unknown and never counts as delivered."""
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ValueError("invalid source SHA for readback")
    req = Request("https://api.github.com/repos/baum777/unitera_marketing_agent-team/commits/"
                  + sha + "/status", method="GET",
                  headers={"Authorization": "Bearer " + token,
                           "Accept": "application/vnd.github+json",
                           "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with (get or build_opener(NoRedirect()).open)(req, timeout=20) as response:
            payload = json.loads(response.read(65536).decode("utf-8"))
    except HTTPError as exc:
        raise RuntimeError("status readback rejected HTTP " + str(exc.code)) from None
    except (URLError, TimeoutError, OSError, ValueError):
        raise RuntimeError("status readback unknown; delivery unverified") from None
    if payload.get("sha") != sha:
        raise RuntimeError("readback SHA mismatch")
    for entry in payload.get("statuses", []):
        if entry.get("context") == STATUS_CONTEXT:
            if entry.get("state") != expect_state:
                raise RuntimeError("readback state mismatch: " + str(entry.get("state")))
            return {"source_sha": sha, "context": STATUS_CONTEXT,
                    "state": entry["state"], "readback_verified": True}
    raise RuntimeError("readback context absent; delivery unverified")
