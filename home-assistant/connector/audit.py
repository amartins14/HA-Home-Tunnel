"""Bounded metadata-only audit storage; write failures stop tunnel readiness."""
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

class StrictRotatingHandler(RotatingFileHandler):
    def handleError(self, record):
        raise OSError('Audit log write failed')

class AuditLog:
    def __init__(self, directory=Path('/data/logs'), max_bytes=10*1024*1024, backups=4):
        directory.mkdir(parents=True, exist_ok=True)
        self.handler = StrictRotatingHandler(directory/'tunnel.jsonl', maxBytes=max_bytes, backupCount=backups, encoding='utf-8')
        self.handler.setFormatter(logging.Formatter('%(message)s'))

    def write(self, record):
        # Callers supply only validated metadata, never headers, bodies or raw URLs.
        line = json.dumps(record, separators=(',', ':'), ensure_ascii=True)
        if len(line) > 65536:
            raise ValueError('Audit record exceeds bound')
        self.handler.handle(logging.LogRecord('audit', logging.INFO, '', 0, line, (), None))
        self.handler.flush()

    def close(self):
        self.handler.close()
