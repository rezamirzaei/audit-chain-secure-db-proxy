from __future__ import annotations

import logging

import urllib3
from urllib3.exceptions import InsecureRequestWarning

from .bootstrap import ProxyCloneBootstrap
from .config import ProxyCloneConfig


class ProxyCloneRuntime:
    def __init__(self, config: ProxyCloneConfig | None = None) -> None:
        self.config = config or ProxyCloneConfig.from_env()
        if not self.config.ssl_verify:
            urllib3.disable_warnings(InsecureRequestWarning)

        self.bootstrap = ProxyCloneBootstrap(self.config)
        self.app = self.bootstrap.create_app()

        logging.basicConfig(level=self.config.log_level)
        self.logger = logging.getLogger("proxy_clone")
