# RAVEN Bug Bounty Checklist

- Confirm the target and all tested hosts are in scope.
- Keep the configured rate limit conservative.
- Do not bypass anti-bot, WAF or access-control systems.
- Reproduce only safe GET, HEAD, OPTIONS and explicitly authorized checks.
- Treat discovered secrets as potential evidence only; never use them.
- Document exact curl commands and response metadata.
