---
name: False positive
about: A finding was reported that is not a real vulnerability
title: "[FP] "
labels: false-positive
---

False positives are the most valuable bug reports this project can receive.
They tell us exactly which heuristic is too loose.

**Which finding**

<!-- The exact title from the report, and the module that produced it. -->

**Target**

<!-- The URL, endpoint or file. -->

**Why it is not real**

<!-- What the application actually does, and why the evidence does not
     support the conclusion. -->

**Evidence**

<!-- Paste the proof block from the console output, or the `evidence`
     section of the JSON report. -->

```
```

**What would have made the scanner correct here**

<!-- e.g. "the baseline should have been length-matched" or "the status
     change alone should not count as injection" -->
