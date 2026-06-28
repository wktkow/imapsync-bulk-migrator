import urllib.parse
import re

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
        """GET wrapper that returns either a JSON object or parsed key-values."""
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
        """POST wrapper that returns either a JSON object or parsed key-values."""
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

    @staticmethod
    def _looks_already_exists(message: str) -> bool:
        return bool(re.search(r"\b(already exists?|exists? already|account exists?|user exists?)\b", message, flags=re.IGNORECASE))

    @staticmethod
    def _looks_not_found(message: str) -> bool:
        return bool(re.search(r"\b(not exist|does not exist|doesn't exist|not found|no such)\b", message, flags=re.IGNORECASE))

    def list_pop_accounts(self, domain: str):
        """Return list of local-part usernames for a domain's POP/IMAP accounts."""
        json_obj, kv = self._get("CMD_API_POP", params={"domain": domain, "action": "list"})
        def _kv_get_one(mapobj, key: str):
            vals = mapobj.get(key)
            return (vals[0] if (vals and len(vals) > 0) else None) if mapobj is not None else None
        if json_obj is not None:
            if isinstance(json_obj, dict):
                has_error = "error" in json_obj
                err = str(json_obj.get("error", "0"))
                if err not in {"0", "false", "False"}:
                    msg = str(json_obj.get("text") or json_obj.get("message") or "DirectAdmin returned error")
                    raise RuntimeError(msg)
                if "list" in json_obj and isinstance(json_obj["list"], list):
                    return [str(u) for u in json_obj["list"]]
                if "users" in json_obj and isinstance(json_obj["users"], list):
                    return [str(u) for u in json_obj["users"]]
                dynamic_values = []
                for k, v in json_obj.items():
                    if isinstance(k, str) and k.startswith("list"):
                        if isinstance(v, list):
                            dynamic_values.extend(v)
                        else:
                            dynamic_values.append(v)
                if dynamic_values:
                    return [str(u) for u in dynamic_values]
                if has_error:
                    return []
                raise RuntimeError("Unable to parse POP account list response from DirectAdmin API")
            elif isinstance(json_obj, list):
                # Some DA variants return a plain JSON array
                return [str(u) for u in json_obj]
        if kv is not None:
            has_error = "error" in kv
            err = _kv_get_one(kv, "error") or "0"
            if err not in {"0", "false", "False"}:
                msg = _kv_get_one(kv, "text") or _kv_get_one(kv, "message") or "DirectAdmin returned error"
                raise RuntimeError(msg)
            items = kv.get("list[]") or kv.get("list") or kv.get("users[]") or kv.get("users")
            if items is None:
                if has_error:
                    return []
                raise RuntimeError("Unable to parse POP account list response from DirectAdmin API")
            return [str(u) for u in items]
        raise RuntimeError("Unable to parse POP account list response from DirectAdmin API")

    def create_pop_account(self, domain: str, local_part: str, password: str, quota_mb: int = 0, *, allow_existing: bool = True) -> None:
        """Create a POP/IMAP mailbox; optionally tolerate already-exists responses."""
        data = {
            "action": "create",
            "domain": domain,
            "user": local_part,
            "passwd": password,
            "passwd2": password,
            "quota": str(int(quota_mb) if quota_mb >= 0 else 0),
            "json": "yes",
        }
        json_obj, kv = self._post("CMD_API_POP", data=data)
        def _kv_get_one(mapobj, key: str):
            vals = mapobj.get(key)
            return (vals[0] if (vals and len(vals) > 0) else None) if mapobj is not None else None
        if json_obj is not None and isinstance(json_obj, dict):
            if "error" not in json_obj:
                raise RuntimeError("Unable to parse POP account create response from DirectAdmin API")
            err = str(json_obj.get("error"))
            if err in {"0", "false", "False"}:
                return
            msg = str(json_obj.get("text") or json_obj.get("message") or "DirectAdmin returned error")
            if allow_existing and self._looks_already_exists(msg):
                return
            raise RuntimeError(msg)
        if kv is not None:
            err = _kv_get_one(kv, "error")
            msg = _kv_get_one(kv, "text") or _kv_get_one(kv, "message") or ""
            if err is None:
                if allow_existing and msg and self._looks_already_exists(msg):
                    return
                raise RuntimeError("Unable to parse POP account create response from DirectAdmin API")
            if err in {"0", "false", "False"} or (allow_existing and msg and self._looks_already_exists(msg)):
                return
            raise RuntimeError(msg or f"DirectAdmin returned error= {err}")
        raise RuntimeError("Unable to parse POP account create response from DirectAdmin API")

    def delete_pop_account(self, domain: str, local_part: str) -> None:
        """Delete a POP/IMAP mailbox; tolerate not-found responses."""
        data = {
            "action": "delete",
            "domain": domain,
            "user": local_part,
            "json": "yes",
        }
        json_obj, kv = self._post("CMD_API_POP", data=data)
        def _kv_get_one(mapobj, key: str):
            vals = mapobj.get(key)
            return (vals[0] if (vals and len(vals) > 0) else None) if mapobj is not None else None
        if isinstance(json_obj, dict):
            if "error" not in json_obj:
                raise RuntimeError("Unable to parse POP account delete response from DirectAdmin API")
            err = str(json_obj.get("error"))
            msg = str(json_obj.get("text") or json_obj.get("message") or "")
            if err in {"0", "false", "False"} or self._looks_not_found(msg):
                return
            raise RuntimeError(msg or "DirectAdmin returned error on delete")
        if kv is not None:
            err = _kv_get_one(kv, "error")
            msg = _kv_get_one(kv, "text") or _kv_get_one(kv, "message") or ""
            if err is None:
                if msg and self._looks_not_found(msg):
                    return
                raise RuntimeError("Unable to parse POP account delete response from DirectAdmin API")
            if err in {"0", "false", "False"} or (msg and self._looks_not_found(msg)):
                return
            raise RuntimeError(msg or f"DirectAdmin returned error= {err}")
        raise RuntimeError("Unable to parse POP account delete response from DirectAdmin API")
