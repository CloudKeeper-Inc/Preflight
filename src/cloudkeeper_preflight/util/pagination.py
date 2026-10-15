from __future__ import annotations


def paginate(client, operation: str, result_key: str, **kwargs) -> list:
    """Wrap a boto3 paginator and return the flat list of items at result_key."""
    paginator = client.get_paginator(operation)
    items: list = []
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(result_key, []))
    return items


def paginate_with_token(
    client,
    operation: str,
    result_key: str,
    token_key: str = "NextToken",
    **kwargs,
) -> list:
    """Manual pagination for APIs without a registered paginator (e.g. ram:GetResourceShares)."""
    items: list = []
    method = getattr(client, operation)
    while True:
        response = method(**kwargs)
        items.extend(response.get(result_key, []))
        token = response.get(token_key)
        if not token:
            return items
        kwargs[token_key] = token
