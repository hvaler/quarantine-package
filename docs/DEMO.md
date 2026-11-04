# Demo script (video, about 3 minutes)

The demo uses the deployed site, `https://<your-dns-name>/`, plus one terminal on the VM for the health check.
The containment moment is step 3.

## 1. The idea (20 s)

**Screen:** the home page. It has the input `name@version` and six demo cards.

**Say:** "Before you install an npm package, Quarantine Package runs it in a sealed sandbox on a Vultr VM. A
model on Vultr Serverless Inference predicts what the package will do, and fixed rules decide from what
really happened."

## 2. A benign package (40 s)

**Click:** `express@4.21.2`.

**Screen:**
- The progress page shows *queued*, then *running*, then the link to the receipt.
- The receipt shows **Verdict: install**, with no rules fired.
- *Prediction vs observed:* network `false` / `false`, **match**.
- *Sandbox destroyed: yes*.

**Say:** "Express loaded inside the sandbox. It tried nothing outside its folder, and the model predicted that."

## 3. The containment moment (70 s)

**Before clicking:** in the VM terminal, start a health loop:

```sh
while true; do curl -s -o /dev/null -w "%{http_code} %{time_total}s\n" https://<your-dns-name>/healthz; sleep 1; done
```

**Click:** "Run demo" on the "Hostile package" card.

**Screen, while it runs:** the terminal keeps printing `200 0.0xs`, so the backend still answers.

**Screen, the receipt:**
- **Verdict: do-not-install** (red), with rules `a` (write to `/etc`), `b` (looks for `docker.sock`) and `d`
  (network attempt carrying a payload).
- The *Observations* table lists:
  - the blocked write to `/etc/qp-fixture-marker`;
  - the home-directory write;
  - the `docker.sock` probe;
  - the key-like env count;
  - the `POST`.
- The *Sinkhole log* holds the only trace of the exfiltration: `POST` to `recolector.example.com`, path
  `/collect` and the payload size. It never reached the internet, because the sandbox network ends at the
  sinkhole.
- *Sandbox destroyed: yes: no container, network or volume of this task remains*.

**Say:** "This package tried to write system files, look for the Docker socket and send data out. All of it
was blocked or caught, the data went only to our sinkhole, and the backend kept answering."

## 4. Clean slate (30 s)

**Click:** "Run demo" on the "Install script that downloads" card.

**Screen:**
- A new task id, with **Verdict: review**.
- The receipt explains that the install script tried the network (rule `f`), with the GET in the sinkhole log
  and no payload.
- *Sandbox destroyed: yes*.

**Say:** "The next task ran in a brand-new sandbox. Nothing from the hostile run carried over, and a
legitimate download is flagged for review, not condemned."

## 5. Close (20 s)

**Screen:** the README section "Known limitations".

**Say:** "Every receipt is public and linkable, the verdict never depends on the model, and the limits are
written down."
