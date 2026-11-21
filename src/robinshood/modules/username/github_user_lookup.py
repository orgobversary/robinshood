from __future__ import annotations

from robinshood.core.types import Finding, ModuleSpec, RunContext

MODULE = ModuleSpec(
    name="github_user_lookup",
    category="username",
    description="Verify a GitHub username exists and retrieve public profile metadata.",
    consumes="username",
    produces=("profile",),
    passive=True,
    source_url="https://api.github.com/users/",
)


def run(target: str, ctx: RunContext) -> list[Finding]:
    url = f"https://api.github.com/users/{target}"
    resp = ctx.http.get(url)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    data = resp.json()

    return [
        Finding(
            type="profile",
            value=data.get("html_url", url),
            module=MODULE.name,
            target=target,
            source_url=url,
            raw={
                k: data.get(k)
                for k in ("name", "company", "blog", "location", "email", "bio", "public_repos", "created_at")
            },
        )
    ]
