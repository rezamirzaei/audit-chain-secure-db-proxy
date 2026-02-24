from __future__ import annotations

import logging
from dataclasses import dataclass

import urllib3
from urllib3.exceptions import InsecureRequestWarning

from .config import ProxyCloneConfig


@dataclass(frozen=True)
class ProxyCloneRuntime:
    config: ProxyCloneConfig
    logger: logging.Logger


def create_runtime(config: ProxyCloneConfig | None = None) -> ProxyCloneRuntime:
    config = config or ProxyCloneConfig.from_env()
    if not config.ssl_verify:
        urllib3.disable_warnings(InsecureRequestWarning)

    logging.basicConfig(level=config.log_level)
    logger = logging.getLogger("proxy_clone")
    return ProxyCloneRuntime(config=config, logger=logger)
