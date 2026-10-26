# Security

Prompt Gauntlet attacks its own toy target app and nothing else. Every attack aims at a local mock
assistant, a dummy canary token and addresses under `example.invalid`. No real system, credential or
third-party service is a target.

## Reporting a problem in this repo
If you find a security problem in this code, such as a committed secret or a way for an agent to step
outside its tool allowlist, open a private security advisory on the repository rather than a public
issue. Expect a first reply within 7 days.

## Findings about other people's products
The case studies cover this project's own defences and its toy app. If the system ever surfaces a
genuine weakness in someone else's product or model, it is not published here. It is reported
privately to the owner first, and only discussed once there is a fix or an agreed window.

## What stays out of the repo
The frozen test set, the generated attack corpus, run databases and any recorded model output stay
private. CI fails if any of them is tracked, and every commit is scanned for secrets.
