from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import List


@dataclasses.dataclass
class Account:
    email: str
    password: str


@dataclasses.dataclass
class ServerConfig:
    host: str
    port: int = 993
    ssl: bool = True
    starttls: bool = False


@dataclasses.dataclass
class Config:
    server: ServerConfig
    accounts: List[Account]

    @staticmethod
    def from_json_file(path: Path) -> "Config":
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            raise ValueError("Config root must be an object")

        server_raw = data.get("server")
        if not isinstance(server_raw, dict):
            raise ValueError("Config must include 'server' object")
        host = server_raw.get("host")
        if not host or not isinstance(host, str):
            raise ValueError("server.host must be a non-empty string")
        port = int(server_raw.get("port", 993))
        use_ssl = bool(server_raw.get("ssl", True))
        starttls = bool(server_raw.get("starttls", False))

        accounts_raw = data.get("accounts")
        if not isinstance(accounts_raw, list) or not accounts_raw:
            raise ValueError("Config must include non-empty 'accounts' array")
        accounts: List[Account] = []
        for idx, item in enumerate(accounts_raw):
            if not isinstance(item, dict):
                raise ValueError(f"accounts[{idx}] must be an object")
            email = item.get("email")
            password = item.get("password")
            if not email or not isinstance(email, str):
                raise ValueError(f"accounts[{idx}].email must be a non-empty string")
            if not isinstance(password, str):
                raise ValueError(f"accounts[{idx}].password must be a string (can be empty)")
            accounts.append(Account(email=email, password=password))

        server = ServerConfig(host=host, port=port, ssl=use_ssl, starttls=starttls)
        return Config(server=server, accounts=accounts)


