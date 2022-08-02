# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
"""
Wrapper functions for reading secrets stored in AWS
"""
import boto3
import base64
import os
import functools
import json
import typing as t

from hmalib.common.logging import get_logger

logger = get_logger(__name__)


class AWSSecrets:
    """
    A class for reading secrets stored in aws
    """

    secrets_client: t.Any

    def __init__(self):
        session = boto3.session.Session()
        self.secrets_client = session.client(service_name="secretsmanager")

    def te_api_key(self) -> str:
        """
        get the ThreatExchange API Key.
        Requires THREAT_EXCHANGE_API_TOKEN_SECRET_NAME be present in environ
        else returns empty string.
        """
        secret_name = os.environ.get("THREAT_EXCHANGE_API_TOKEN_SECRET_NAME")
        if not secret_name:
            logger.warning(
                "Unable to load THREAT_EXCHANGE_API_TOKEN_SECRET_NAME from env"
            )
            return ""
        return self._get_str_secret(secret_name)

    @functools.lru_cache(maxsize=1)
    def hma_api_tokens(self) -> t.List[str]:
        """
        get the set of API tokens for auth of the HMA API.
        Requires HMA_ACCESS_TOKEN_SECRET_NAME be present in environ
        else returns empty list.
        """
        secret_name = os.environ.get("HMA_ACCESS_TOKEN_SECRET_NAME")
        if not secret_name:
            logger.warning("Unable to load HMA_ACCESS_TOKEN_SECRET_NAME from env")
            return []
        access_tokens = self._get_str_secret(secret_name)
        return json.loads(access_tokens)

    def _get_bin_secret(self, secret_name: str) -> bytes:
        """
        For secerts stored in AWS Secrets Manager as binary
        """
        response = self._get_secret_value_response(secret_name)
        return base64.b64decode(self._get_secret_value_response("SecretBinary"))

    def _get_str_secret(self, secret_name: str) -> str:
        """
        For secerts stored in AWS Secrets Manager as strings
        """
        response = self._get_secret_value_response(secret_name)
        return response["SecretString"]

    def _get_secret_value_response(self, secret_name: str):
        return self.secrets_client.get_secret_value(SecretId=secret_name)
