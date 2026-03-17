# RE-Bench Formal Scoring Rubric

RE-Bench evaluates reverse engineering LLMs across seven orthogonal axes:

1. Malware Behavior Understanding
2. Vulnerability Detection
3. MITRE ATT&CK Technique Mapping
4. Capability Extraction
5. Assembly & Behavior Analysis (LLM Judge)
6. Explanation Quality
7. Hallucination Robustness

Each axis is scored independently and combined into a weighted composite.

---

## 1️⃣ Malware Behavior Classification

**Task Type:** Multi-label classification  
**Datasets:** EMBER, MalwareBazaar  
**Metric:** Macro F1

| Score Range | Interpretation |
|-------------|---------------|
| 0.90–1.00 | Near-human malware family understanding |
| 0.75–0.89 | Strong detection, minor confusion |
| 0.60–0.74 | Moderate understanding |
| < 0.60 | Weak malware comprehension |

Macro F1 is used to avoid majority-class bias.

---

## 2️⃣ Vulnerability Detection (CWE-Level)

**Task Type:** Multi-class or multi-label CWE prediction  
**Datasets:** Big-Vul, Juliet  
**Metrics:**
- Macro F1 (primary)
- Precision / Recall
- Per-CWE F1 (secondary)

### Auto-CWE F1 Formula

For each CWE:

F1 = 2 × (Precision × Recall) / (Precision + Recall)

Macro-F1 across all CWEs is reported as primary score.

---

## 3️⃣ MITRE ATT&CK Technique Mapping

**Task Type:** Single-label classification  
**Datasets:** BIG-15, MELD  
**Metric:** Accuracy (with normalization)

Predictions are normalized before comparison:
- Synonyms resolved (e.g. `"process injection"` → `T1055`)
- Sub-techniques collapsed to base technique (e.g. `T1055.001` → `T1055`)

| Score Range | Interpretation |
|-------------|---------------|
| 0.85–1.00 | Strong ATT&CK knowledge |
| 0.65–0.84 | Moderate technique recognition |
| < 0.65 | Weak technique mapping |

---

## 4️⃣ Capability Extraction

**Task Type:** Multi-label extraction  
**Datasets:** MELD, Malrec  
**Metric:** Macro F1 (token-level, after capability normalization)

Capability synonyms are normalized before scoring
(e.g. `"dll injection"` → `"process injection"`).

| Score Range | Interpretation |
|-------------|---------------|
| 0.80–1.00 | Accurate capability identification |
| 0.60–0.79 | Partial capability coverage |
| < 0.60 | Significant capability gaps |

---

## 5️⃣ Assembly & Behavior Analysis (LLM Judge)

**Task Type:** Free-text generation  
**Datasets:** BIG-15 (assembly understanding), MELD / Malrec (behavior explanation)  
**Metric:** Rubric score 0–3, normalized to \[0, 1\]

### Rubric

| Score | Criteria |
|-------|----------|
| 3 | Correct technique/behavior identified with accurate supporting detail |
| 2 | Correct identification, minor inaccuracies in detail |
| 1 | Partially correct — relevant but incomplete or imprecise |
| 0 | Incorrect, irrelevant, or no response |

### Normalized Score

$$\text{Judge Score} = \frac{\text{raw rubric score}}{3}$$

A heuristic keyword-overlap fallback is used when an LLM judge is unavailable
(≥0.75 overlap → 3, ≥0.50 → 2, ≥0.25 → 1, else 0).

---

## 6️⃣ Explanation Quality

**Task Type:** Free-text explanation generation  
**Metrics:**
- ROUGE-L
- BERTScore F1

| Score | Interpretation |
|-------|---------------|
| > 0.85 BERTScore | High semantic alignment |
| 0.70–0.85 | Reasonable explanation |
| < 0.70 | Low semantic similarity |

Human spot-check validation is recommended for publication.

---

## 7️⃣ Hallucination Robustness

Measured using:

- Unsupported claim rate
- Binary contradiction rate
- Out-of-scope CWE hallucination frequency

### Hallucination Score

Hallucination Score = 1 − (False Claims / Total Claims)

---

## 🏆 Composite Score

Default weights:

| Metric | Weight | Datasets |
|--------|--------|---------|
| Malware F1 | 0.20 | EMBER, MalwareBazaar |
| CWE F1 | 0.20 | Big-Vul, Juliet |
| MITRE Mapping Accuracy | 0.15 | BIG-15, MELD |
| Capability Extraction F1 | 0.15 | MELD, Malrec |
| Assembly / Behavior Judge | 0.15 | BIG-15, MELD, Malrec |
| Explanation Similarity | 0.10 | All |
| Hallucination Robustness | 0.05 | All |

Composite = Weighted Sum

Weights may be adjusted but must be reported.