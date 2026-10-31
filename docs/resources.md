# Resources

Tools, data, designs and practice ranges that could help this project later. None of them is used
yet, and none may be cited: for each one only the repo or page and its licence were checked, on
2026-10-31, not what it claims to do. Papers and posts that were checked properly are in
`docs/references.md`. Most of these were found through the community list
[awesome-prompt-injection](https://github.com/Joe-B-Security/awesome-prompt-injection).

A new data source needs the operator's approval, a licence check and a rebuild of the dataset, and a
rebuild means the checker pass runs again (PLAN section 7). Anything that attacks something is aimed
only at the local toy app.

## Detectors and attack sources

| Name | Owner | Licence | What it could do here | PLAN | Checked |
|---|---|---|---|---|---|
| [PIGuard](https://github.com/leolee99/PIGuard) (formerly InjecGuard) | leolee99 | MIT | The open-weights classifier baseline, a DeBERTa model with published weights; whether it gives a score or only a label is not yet known | 8 | repo and licence file; claims not verified |
| [garak](https://github.com/NVIDIA/garak) | NVIDIA | Apache-2.0 | Probe library for a static set of attacks not written by the project's own model family | 7 | repo and licence file; claims not verified |
| [Augustus](https://github.com/praetorian-inc/augustus) | Praetorian | Apache-2.0 | A second probe library for the same purpose | 7 | repo and licence file; claims not verified |
| [Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules) | Agent-Threat-Rule | MIT | Rule ideas for the regex baseline and the hill-climb bank, each checked against the held-out techniques first | 8, 14 | repo and licence file; claims not verified |

## Attack data tied to actions

About a third of the current attacks ask for something the toy app cannot show (`docs/run-record.md`).
These sets are built around actions an agent takes.

| Name | Owner | Licence | Notes | Checked |
|---|---|---|---|---|
| [FinAgent Red-Team](https://github.com/nac7/finagent-redteam) | nac7 | MIT | Synthetic scenarios for financial agents, with a datasheet | repo and licence file; claims not verified |
| The 847-case benchmark | Ramakrishnan and Balaji | see the paper | `docs/references.md` entry 16 | paper verified; data not yet located |
| AgentPI | Wang, Li, Xiang et al. | see the paper | `docs/references.md` entry 15 | paper verified; data not yet located |
| [trapcheck corpus](https://github.com/agentatwork/trapcheck/blob/main/CORPUS.md) | agentatwork | MIT | Notes from one live campaign aimed at agents; field evidence, not labelled data | repo and licence file; claims not verified |

## Designs for the structural arms (Phase 4)

| Name | Owner | Licence | What it is | Checked |
|---|---|---|---|---|
| [PIC Standard](https://github.com/pic-standard/pic-standard) | pic-standard | Apache-2.0 | Intent and provenance checks before an agent's action, close to the capability-gate arm | repo and licence file; claims not verified |
| [Guard Bands](https://github.com/Cryptix-Security/guard-bands) | Cryptix-Security | MIT | Described as signed boundaries around untrusted content, close to spotlighting | repo and licence file; claims not verified |
| FIDES | Microsoft | see the paper | Information-flow control for agents, named in `docs/references.md` entry 22; the paper itself is not yet checked | post verified; paper not |
| [Agent Memory Guard](https://github.com/OWASP/www-project-agent-memory-guard) | OWASP | Apache-2.0 | Defence against memory poisoning, for the memory-safety work (PLAN section 9, v2) | repo and licence file; claims not verified |

## Practice ranges, for the technique journal (PLAN section 3c)

| Name | Owner | Licence | Checked |
|---|---|---|---|
| [Damn Vulnerable LLM Agent](https://github.com/ReversecLabs/damn-vulnerable-llm-agent) | ReversecLabs | Apache-2.0 | repo and licence file |
| [ai-prompt-ctf](https://github.com/c-goosen/ai-prompt-ctf) | c-goosen | MIT | repo and licence file |
| [PromptTrace](https://prompttrace.airedlab.com/) | airedlab | CC BY 4.0, as the site states | site |
| Gandalf | Lakera | none stated | `docs/references.md` entry 14 |

## Further reading, not verified

- OpenAI, "Continuously hardening ChatGPT Atlas against prompt injection" (the page could not be
  read directly; described elsewhere as an automated attacker trained against the browser agent).
- WithSecure, "Synthetic Recollections", a case study of hijacking a ReAct agent loop (its address
  now redirects to an index).
- StackOne, "Indirect Prompt Injection Defense for MCP Tools: A Technical Guide" (vendor post).
- Alex Churilov, on a class of attack that passes a content-based MCP detector (dev.to).
- prompt-shield, a detection engine whose paper is written by its own author, with results on a
  54-item self-curated set.
