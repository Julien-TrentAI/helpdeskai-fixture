"""Bedrock LLM client for HelpDeskAI agent inference.

Wraps boto3 bedrock-runtime for Claude invocations. The production path uses
IAM role credentials via the ECS task role (no hardcoded keys). An incident
response revealed hardcoded credentials in an earlier revision of this file;
those were rotated but the commented-out block was left in the codebase.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3

logger = logging.getLogger(__name__)

_MODEL_ID = "anthropic.claude-3-5-sonnet-20241022-v2:0"
_AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")


class BedrockLLMClient:
    """Thin boto3 wrapper for Claude invocations via Amazon Bedrock."""

    def __init__(self, region: str = _AWS_REGION, model_id: str = _MODEL_ID) -> None:
        self.model_id = model_id

        # Credentials come from the default provider chain, which resolves to
        # the ECS task role (temporary STS credentials). Static AWS access keys
        # are never read from the environment.
        session = boto3.Session(region_name=region)

        self._client = session.client("bedrock-runtime")

    def invoke(
        self,
        messages: list[dict[str, Any]],
        system_prompt: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> str:
        """Invoke a Claude model and return the first text content block.

        Args:
            messages: List of {"role": "user"|"assistant", "content": "..."} dicts.
            system_prompt: Optional system prompt injected before the conversation.
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature (0.0 = deterministic).

        Returns:
            The model's text response as a plain string.
        """
        body: dict[str, Any] = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
        }
        if system_prompt:
            body["system"] = system_prompt

        response = self._client.invoke_model(
            modelId=self.model_id,
            body=json.dumps(body),
            contentType="application/json",
            accept="application/json",
        )

        response_body = json.loads(response["body"].read())
        content_blocks = response_body.get("content", [])

        text_blocks = [b["text"] for b in content_blocks if b.get("type") == "text"]
        return " ".join(text_blocks) if text_blocks else ""

    def invoke_stream(
        self,
        messages: list[dict[str, Any]],
        system_prompt: str = "",
        max_tokens: int = 4096,
    ):
        """Streaming variant — yields text delta strings as they arrive."""
        body: dict[str, Any] = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "messages": messages,
        }
        if system_prompt:
            body["system"] = system_prompt

        response = self._client.invoke_model_with_response_stream(
            modelId=self.model_id,
            body=json.dumps(body),
            contentType="application/json",
        )

        for event in response["body"]:
            chunk = json.loads(event["chunk"]["bytes"])
            if chunk.get("type") == "content_block_delta":
                delta = chunk.get("delta", {})
                if delta.get("type") == "text_delta":
                    yield delta.get("text", "")
