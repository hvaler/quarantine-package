# L-20 evidence: changes to the "What happened" vocabulary (S8)

The guard on the informational "What happened" text accepts a reply only if every word is in a
fixed descriptive vocabulary (`VOCABULARY` in `src/outcome.js`). See README L-20 for the whole guard.

In S8, a diagnosis with the real Vultr Serverless Inference endpoint (`mimo-v2.6-pro`) captured the
replies the guard rejected. It ran the product's `explain()` on the six stored demo receipts, three
rounds, 18 calls. The rejected texts stay in the band's `checks/` evidence, never in this repository.

A word was added only if the diagnosis needed it **and** it is purely descriptive. The S7 rules still
exclude:
- any word in the S7 banned or phrase tables;
- verdict-family stems;
- safety, judgement, advice and modal words;
- negations and minimisers;
- words that move an act off the package (`npm`, `harness`).

Every addition is reviewed by the band's adversary. The code reasons are in `S8_ADDITIONS`.

## Added

"Rejected by" is the guard step that rejected the reply holding the word. "Seen" is the number of
rejected replies with it, out of 18 diagnosis calls.

| Word | Rejected by | Seen | Why it is purely descriptive |
|---|---|---|---|
| `dimensions` | vocabulary | 4 | the three predicted dimensions (network, files, processes) |
| `dimension` | vocabulary | 0 | singular of `dimensions` |
| `matching` | vocabulary | 3 | participle of `matched`, which is already allowed (prediction vs observed) |
| `enumerated` | vocabulary | 2 | listed the environment variables (the env-enumerate observation) |
| `behavior` | vocabulary | 2 | what the package did, as a noun with no judgement ("expected", "normal" and similar stay out) |
| `behaviour` | vocabulary | 0 | British spelling of `behavior` |
| `resource` | vocabulary | 2 | rule (e) text: "task ended by a resource or time limit" |
| `resources` | vocabulary | 0 | plural of `resource` |
| `touching` | vocabulary | 1 | participle of `touched`, which is already allowed |
| `up` | vocabulary | 1 | the particle in "looked up" (a DNS lookup) |
| `measured` | vocabulary | 1 | past tense: the measured dimensions |
| `runtime` | vocabulary | 1 | container runtime, the socket that rule (b) looks for |
| `directly` | vocabulary | 1 | adverb of manner: started directly, without a shell |
| `seen` | vocabulary | 1 | past participle: seen in the trace |
| `across` | vocabulary | 1 | preposition: across the three dimensions |
| `exhausted` | vocabulary | 1 | the pids limit was exhausted (rule e) |
| `forked` | vocabulary | 1 | past tense of `fork`, which is already allowed as a noun |
| `entered` | vocabulary | 1 | past tense: entered a loop |
| `task` | vocabulary | 1 | the analysis task, a receipt term ("ended the task") |

## Not added, though the diagnosis showed them

| Word(s) | Why they stay out |
|---|---|
| `run` (4) | "Run it." is advice to install; the prompt says "the analysis" instead |
| `stayed`, `kept` (1 each) | containment denial: "Rule (a) fired; the package stayed in its folder" (or "kept to its folder") contradicts the finding with allowed words only. Proposed in the first S8 draft, withdrawn before review (analyst note b0e3fe2b). |
| `plain` (1) | judgement: "plain behaviour" reads as ordinary/benign; "plaintext" is already allowed. Withdrawn (auditor note e6e70340). |
| `completed`, `finished` (1 each) | misdescribe a task that rule (e) says a limit ended ("the task completed"). Withdrawn (auditor note e6e70340). |
| `harness` (3) | it moves an act off the package |
| `load` (3) | bare imperative ("Load it."); `loaded` and `loading` are allowed |
| `successfully`, `well`, `normally` | judgement words |
| `could`, `use`, `because`, `further` | a modal, an advice verb, a causal claim, an open-ended intensifier |
| `never` | a negation |
| `require`, `fallback` | harness internals |
| `post` | a bare verb ("post it"); "POST request" is accepted through the S7 method-phrase rule |
| `checks` | not needed after the prompt change |
| `touch`, `prebuilt`, `manifest`, `recursively`, `runaway`, `growth`, `endless`, `spinning` | not needed for the demos after the prompt change; kept out to keep the list minimal |

## Removed

| Word | Why |
|---|---|
| `zero` | The diagnosis produced "touched zero files" on a do-not-install receipt. That carries a denial past the negation check, so it is removed. This makes the guard stricter, never looser. |
