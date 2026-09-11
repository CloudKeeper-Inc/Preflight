"""Bedrock Sonnet 5 email drafter.

Turns a summariser output dict into the plain-text email body ready for
analyst review. Uses the Converse API + the US inference profile in
us-east-1.

CLI:  python -m cloudkeeper_preflight.email_gen.bedrock <assessment.json[.gz]>
        Runs the summariser on the assessment, sends to Sonnet 5, prints the
        email body to stdout.
"""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

import boto3

from .prompt_templates import (
    ONE_SHOT_INPUT,
    ONE_SHOT_OUTPUT,
    SYSTEM_PROMPT,
)
from .summariser import summarize_for_email

_MODEL_ID = "us.anthropic.claude-sonnet-5"
_REGION = "us-east-1"
# Bedrock's Sonnet-5 cap is generous but the email is short — 4k is plenty
# and prevents a runaway if the prompt goes wrong.
_MAX_OUTPUT_TOKENS = 4096


def generate_email(summary: dict, *, client=None) -> tuple[str, dict]:
    """Draft the customer email from a summariser output.

    Returns (body, usage). `body` is finished plain text — the prompt
    forbids Markdown markup, since the analyst pastes this straight into a
    mail client. `usage` is Bedrock's token counter dict — handy for cost
    tracking during prompt iteration.
    """
    client = client or boto3.client("bedrock-runtime", region_name=_REGION)

    messages = [
        {
            "role": "user",
            "content": [{"text": _user_turn(ONE_SHOT_INPUT)}],
        },
        {
            "role": "assistant",
            "content": [{"text": ONE_SHOT_OUTPUT}],
        },
        {
            "role": "user",
            "content": [{"text": _user_turn(summary)}],
        },
    ]

    response = client.converse(
        modelId=_MODEL_ID,
        system=[{"text": SYSTEM_PROMPT}],
        messages=messages,
        inferenceConfig={"maxTokens": _MAX_OUTPUT_TOKENS},
        # Sonnet 5 enables extended thinking by default; the reasoning
        # tokens eat the maxTokens budget without any benefit for this
        # template-substitution task.
        additionalModelRequestFields={"thinking": {"type": "disabled"}},
    )

    text = _extract_text(response)
    return text, response.get("usage", {})


def _extract_text(response: dict) -> str:
    """Pull the assistant's text block out of a Converse response.

    Sonnet 5's response can interleave `reasoningContent`, `text`, and other
    block kinds; the email is always in a `text` block. Concatenate all
    `text` blocks in order in case the model split the answer.
    """
    parts: list[str] = []
    for blk in response["output"]["message"]["content"]:
        if "text" in blk:
            parts.append(blk["text"])
    return "".join(parts)


def _user_turn(summary: dict) -> str:
    """Frame the summary dict as the user turn."""
    return (
        "Draft the onboarding email for the customer described by the "
        "following summary dict. Follow every rule in the system prompt.\n\n"
        "```json\n"
        + json.dumps(summary, indent=2, default=str)
        + "\n```"
    )


def _load(path: Path) -> dict:
    if path.suffix == ".gz" or path.name.endswith(".json.gz"):
        with gzip.open(path, "rb") as f:
            return json.loads(f.read())
    with path.open() as f:
        return json.load(f)


def main() -> None:
    if len(sys.argv) != 2:
        print(
            "usage: python -m cloudkeeper_preflight.email_gen.bedrock "
            "<assessment.json[.gz]>",
            file=sys.stderr,
        )
        sys.exit(2)
    assessment = _load(Path(sys.argv[1]))
    summary = summarize_for_email(assessment)
    text, usage = generate_email(summary)
    print(text)
    print(
        f"\n--- usage: input={usage.get('inputTokens')} "
        f"output={usage.get('outputTokens')} "
        f"total={usage.get('totalTokens')} ---",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
