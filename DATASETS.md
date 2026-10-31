# Datasets

Every third-party dataset used by the project is listed here with its licence and attribution before
any of it is loaded. A dataset whose licence forbids redistribution is referenced, never copied in.

None of it is redistributed here: the build fetches each file at a pinned revision into the private,
gitignored `private/data/raw/` (`python -m arena.cli data fetch`), and the built data stays private.
Licences are as recorded in `arena/data/sources.toml`. Attack text has every address and URL host
replaced with a placeholder, so no attack names a real endpoint; benign email has addresses and
phone numbers scrubbed.

Items are counted from the real build of 27 October 2026, across the Judge partitions and train, after
deduplication.

| Dataset | Source | Licence | Used for | Items in the build | Redistributed here |
|---|---|---|---|---|---|
| BIPIA (attack instruction lists only) | [microsoft/BIPIA](https://github.com/microsoft/BIPIA) | MIT code; data licence not stated, used privately | Attacks | 250 attacks | No |
| InjecAgent | [uiuc-kang-lab/InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | MIT, with notice | Attacks | 124 attacks | No |
| AgentDojo | [ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo) | MIT, with notice | Attacks and benign tasks | 129 attacks, 30 benign | No |
| LLMail-Inject | [microsoft/llmail-inject-challenge](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) | MIT, with notice | Attacks | 2,682 attacks | No |
| Enron email | [CMU Enron corpus](https://www.cs.cmu.edu/~enron/) | No licence; public resource for research purposes. Private only | Benign email | 2,881 benign | No |
| Dolly 15k | [databricks/databricks-dolly-15k](https://huggingface.co/datasets/databricks/databricks-dolly-15k) | CC BY-SA 3.0, share-alike and attribution | Benign instructions | 2,984 benign | No |
| OWASP Cheat Sheet Series | [OWASP/CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries) | CC-BY-SA-4.0, attribution and share-alike | Benign security documents | 2,966 benign | No |
| CodeSearchNet | [code-search-net/code_search_net](https://huggingface.co/datasets/code-search-net/code_search_net) | Per-repository licences; private only | Benign code | 2,980 benign | No |

Not in the build:
- deepset prompt-injections ([deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections),
  Apache-2.0, attribution) is fetched only to check the labellers, never as data.
- Tatoeba ([Helsinki-NLP/tatoeba_mt](https://huggingface.co/datasets/Helsinki-NLP/tatoeba_mt), CC-BY
  2.0, attribution) is approved but was not fetched: its files are gated.

Candidate sources that are not used are listed in `docs/resources.md`.
