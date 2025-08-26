import urllib.parse

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore


class DirectAdminClient:
    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = True, timeout_sec: int = 20) -> None:
        if requests is None:  # type: ignore
            raise RuntimeError("DirectAdmin auto-provisioning requires the 'requests' package. Install it via: pip install -r requirements.txt")
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()  # type: ignore
        self.session.auth = (username, password)
        self.session.verify = verify_ssl
        self.timeout_sec = timeout_sec

    def _endpoint(self, path: str) -> str:
        if path.startswith("/"):
            return f"{self.base_url}{path}"
        return f"{self.base_url}/{path}"

    def _get(self, path: str, params=None):
        params = dict(params or {})
        params.setdefault("json", "yes")
        url = self._endpoint(path)
        resp = self.session.get(url, params=params, timeout=self.timeout_sec)
        resp.raise_for_status()
        ctype = resp.headers.get("Content-Type", "").lower()
        if "json" in ctype:
            try:
                return resp.json(), None
            except Exception:
                pass
        text = resp.text.strip()
        if text.startswith("{") or text.startswith("["):
            try:
                return resp.json(), None
            except Exception:
                pass
        parsed = urllib.parse.parse_qs(text, keep_blank_values=True, strict_parsing=False)
        return None, parsed

    def _post(self, path: str, data):
        url = self._endpoint(path)
        resp = self.session.post(url, data=data, timeout=self.timeout_sec)
        resp.raise_for_status()
        ctype = resp.headers.get("Content-Type", "").lower()
        if "json" in ctype:
            try:
                return resp.json(), None
            except Exception:
                pass
        text = resp.text.strip()
        if text.startswith("{") or text.startswith("["):
            try:
                return resp.json(), None
            except Exception:
                pass
        parsed = urllib.parse.parse_qs(text, keep_blank_values=True, strict_parsing=False)
        return None, parsed

    def list_pop_accounts(self, domain: str):
        json_obj, kv = self._get("CMD_API_POP", params={"domain": domain, "action": "list"})
        if json_obj is not None:
            if isinstance(json_obj, dict):
                if "list" in json_obj and isinstance(json_obj["list"], list):
                    return [str(u) for u in json_obj["list"]]
                if "users" in json_obj and isinstance(json_obj["users"], list):
                    return [str(u) for u in json_obj["users"]]
            dynamic = [v for k, v in json_obj.items() if isinstance(k, str) and k.startswith("list")]
            if dynamic:
                return [str(u) for u in dynamic]
        if kv is not None:
            items = kv.get("list[]") or kv.get("list") or kv.get("users[]") or kv.get("users") or []
            return [str(u) for u in items]
        return []

    def create_pop_account(self, domain: str, local_part: str, password: str, quota_mb: int = 0) -> None:
        data = {
            "action": "create",
            "domain": domain,
            "user": local_part,
            "passwd": password,
            "passwd2": password,
            "quota": str(int(quota_mb) if quota_mb >= 0 else 0),
        }
        json_obj, kv = self._post("CMD_API_POP", data=data)
        def _kv_get_one(mapobj, key: str):
            vals = mapobj.get(key)
            return (vals[0] if (vals and len(vals) > 0) else None) if mapobj is not None else None
        if json_obj is not None and isinstance(json_obj, dict):
            err = str(json_obj.get("error", "0"))
            if err in {"0", "false", "False"}:
                return
            msg = str(json_obj.get("text") or json_obj.get("message") or "DirectAdmin returned error")
            if "exist" in msg.lower():
                return
            raise RuntimeError(msg)
        if kv is not None:
            err = _kv_get_one(kv, "error") or "0"
            msg = _kv_get_one(kv, "text") or _kv_get_one(kv, "message") or ""
            if err in {"0", "false", "False"} or (msg and "exist" in msg.lower()):
                return
            raise RuntimeError(msg or f"DirectAdmin returned error= {err}")


