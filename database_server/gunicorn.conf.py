bind = "0.0.0.0:5000"
workers = int(__import__('os').environ.get("WEB_CONCURRENCY", "2"))
threads = int(__import__('os').environ.get("WEB_THREADS", "4"))
timeout = int(__import__('os').environ.get("WEB_TIMEOUT", "60"))
accesslog = "-"
errorlog = "-"
