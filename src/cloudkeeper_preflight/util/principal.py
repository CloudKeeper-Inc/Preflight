from __future__ import annotations


def short_service_name(principal: str) -> str:
    """Compact label for an AWS service principal, used in coverage_gaps output.

    Examples:
        cloudtrail.amazonaws.com                              -> cloudtrail
        member.org.stacksets.cloudformation.amazonaws.com     -> stacksets
        reporting.trustedadvisor.amazonaws.com                -> trustedadvisor
        cost-optimization-hub.bcm.amazonaws.com               -> bcm
    """
    if not principal:
        return "unknown"
    head = principal.split(".amazonaws.com", 1)[0]
    return head.rsplit(".", 1)[-1] or principal
