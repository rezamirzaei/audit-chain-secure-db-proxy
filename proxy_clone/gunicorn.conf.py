import os

bind = "0.0.0.0:8080"
workers = int(os.environ.get("WEB_CONCURRENCY", "2"))
threads = int(os.environ.get("WEB_THREADS", "4"))
timeout = int(os.environ.get("WEB_TIMEOUT", "60"))
accesslog = "-"
errorlog = "-"
