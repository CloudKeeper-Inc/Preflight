from __future__ import annotations

from datetime import datetime

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate

_ROOT_PATH_LABEL = "Root"


def assess_accounts(
    session=None,
    ou_tree: list[dict] | None = None,
    root_id: str | None = None,
) -> tuple[list[dict], list[dict]]:
    """List all accounts in the org with their OU placement.

    `ou_tree` and `root_id` are produced by `assess_organization()` and used
    to render the human-readable OU path. If they're missing the path falls
    back to just the immediate parent ID.
    """
    errors: list[dict] = []
    client = create_client("organizations", region="us-east-1", session=session)

    try:
        raw_accounts = paginate(client, "list_accounts", "Accounts")
    except ClientError as exc:
        errors.append(
            {
                "module": "accounts",
                "operation": "ListAccounts",
                "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                "message": str(exc),
            }
        )
        return [], errors

    ou_index = _index_ou_tree(ou_tree or [])
    accounts: list[dict] = []

    for acct in raw_accounts:
        account_id = acct["Id"]
        parent_id = None
        try:
            parents = paginate(
                client, "list_parents", "Parents", ChildId=account_id
            )
            if parents:
                parent_id = parents[0]["Id"]
        except ClientError as exc:
            errors.append(
                {
                    "module": "accounts",
                    "operation": "ListParents",
                    "account_id": account_id,
                    "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                    "message": str(exc),
                }
            )

        accounts.append(
            {
                "account_id": account_id,
                "name": acct.get("Name"),
                "email": acct.get("Email"),
                "status": acct.get("Status"),
                "joined_method": acct.get("JoinedMethod"),
                "joined_timestamp": _to_iso(acct.get("JoinedTimestamp")),
                "ou_id": parent_id,
                "ou_path": _build_ou_path(parent_id, ou_index, root_id),
            }
        )

    return accounts, errors


def _index_ou_tree(tree: list[dict]) -> dict[str, dict]:
    """Flatten the OU tree into {ou_id: {'name': str, 'parent_id': str}}."""
    index: dict[str, dict] = {}

    def walk(nodes: list[dict]) -> None:
        for node in nodes:
            index[node["ou_id"]] = {
                "name": node["ou_name"],
                "parent_id": node["parent_id"],
            }
            walk(node.get("children", []))

    walk(tree)
    return index


def _build_ou_path(
    parent_id: str | None,
    ou_index: dict[str, dict],
    root_id: str | None,
) -> str:
    if parent_id is None:
        return ""
    if root_id is not None and parent_id == root_id:
        return _ROOT_PATH_LABEL

    chain: list[str] = []
    cursor = parent_id
    visited: set[str] = set()
    while cursor and cursor not in visited:
        visited.add(cursor)
        node = ou_index.get(cursor)
        if not node:
            chain.append(cursor)
            break
        chain.append(node["name"])
        next_parent = node["parent_id"]
        if root_id is not None and next_parent == root_id:
            break
        cursor = next_parent

    chain.reverse()
    return " / ".join([_ROOT_PATH_LABEL, *chain])


def _to_iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
