# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

import os
import os.path
import sys
import typing as t

from flask import current_app


class HmaLiteConfig(t.NamedTuple):
    """
    Flask configs are a bit derpy, do what they should have done.

    Allows typing, as well as smart loading from environment, though
    that only works with types that can take a str as an argument
    """

    DEBUG: bool = True
    TESTING: bool = False

    STATE_DIR: str = os.path.expanduser("~/.hmalite/")

    CSV_FILE: str = ""
    INDEX_FILE: str = ""
    # Relative to state dir, but probably don't do that intentionally
    UPLOADS_FOLDER: str = "uploads/"

    @classmethod
    def init_with_environ(cls) -> "HmaLiteConfig":
        kwargs = {
            name: py_type(os.environ[name])
            for name, py_type in cls._field_types.items()
            if name in os.environ
        }

        return cls(**kwargs)

    @classmethod
    def from_flask_current_app(cls) -> "HmaLiteConfig":
        """Init from current flask config"""
        return cls(**{k: v for k, v in current_app.config.items() if k in cls._fields})

    # Helper methods
    def create_dirs(self):
        os.makedirs(self.STATE_DIR, exist_ok=True)
        os.makedirs(self.upload_folder, exist_ok=True)

    def _exists(self, path):
        return path if path and os.path.exists(path) else ""

    @property
    def upload_folder(self):
        return os.path.join(self.STATE_DIR, self.UPLOADS_FOLDER)

    @property
    def starting_index_files(self):
        csv_f = self._exists(self.CSV_FILE)
        index_f = (
            "" if csv_f else self._exists(self.INDEX_FILE) or self.local_index_file
        )

        return csv_f, index_f

    @property
    def local_index_file_path(self):
        return os.path.join(self.STATE_DIR, "index.te")

    @property
    def local_index_file(self):
        """Shortcut for checking existence"""
        return self._exists(self.local_index_file_path)


class HmaLiteProdConfig(HmaLiteConfig):
    pass


class HmaLiteDevConfig(HmaLiteConfig):
    DEBUG = True
