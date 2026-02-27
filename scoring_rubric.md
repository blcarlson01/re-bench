# RE-Bench Formal Scoring Rubric

RE-Bench evaluates reverse engineering LLMs across four orthogonal axes:

1. Malware Behavior Understanding
2. Vulnerability Detection
3. Explanation Quality
4. Hallucination Robustness

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

## 3️⃣ Explanation Quality

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

## 4️⃣ Hallucination Robustness

Measured using:

- Unsupported claim rate
- Binary contradiction rate
- Out-of-scope CWE hallucination frequency

### Hallucination Score

Hallucination Score = 1 − (False Claims / Total Claims)

---

## 🏆 Composite Score

Default weights:

| Metric | Weight |
|--------|--------|
| Malware F1 | 0.30 |
| CWE F1 | 0.35 |
| Explanation Similarity | 0.20 |
| Hallucination Robustness | 0.15 |

Composite = Weighted Sum

Weights may be adjusted but must be reported.