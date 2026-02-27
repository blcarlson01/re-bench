# RE-Bench Verification Specification (LLM-Oriented)

This document defines the structural, functional, and behavioral requirements
that must be satisfied for RE-Bench to be considered correctly implemented.

An automated LLM verifier should use this document to statically and dynamically
analyze the source tree and confirm compliance.

---

# 1. REQUIRED REPOSITORY STRUCTURE

The repository MUST contain the following directories:

rebench/
├── configs/
├── data/
│   ├── datasets/
│   ├── ember_loader.py
│   ├── bigvul_loader.py
│   ├── juliet_loader.py
│   └── malwarebazaar_loader.py
├── tasks/
│   ├── ember_task.py
│   ├── bigvul_task.py
│   ├── juliet_task.py
│   └── malwarebazaar_task.py
├── scorers/
│   ├── malware_scorer.py
│   ├── vuln_f1_scorer.py
│   ├── explanation_similarity_scorer.py
│   └── hallucination_scorer.py
├── analysis/
│   ├── load_results.py
│   ├── compute_metrics.py
│   ├── plots.py
│   ├── hallucination_taxonomy.py
│   ├── phoenix_to_df.py
│   └── run_analysis.py
└── scripts/

Failure to include any of these files constitutes an incomplete implementation.

---

# 2. DATASET LOADERS REQUIREMENTS

Each loader MUST:

1. Return a pandas DataFrame
2. Normalize column names to match task expectations
3. Include the required ground truth field:

Dataset Requirements:

EMBER:
  - sha256
  - true_behavior (malware|benign)

Big-Vul:
  - sample_id
  - code
  - cwe

Juliet:
  - sample_id
  - code
  - cwe

MalwareBazaar:
  - sample_id
  - family
  - file_type

The loader must NOT perform model inference.

---

# 3. TASK REQUIREMENTS (Inspect-AI)

Each task file MUST:

1. Use @task decorator from inspect_ai
2. Accept a `sample`
3. Call `sample.model(prompt)`
4. Return structured output as dict
5. Include ground truth field for scoring

Required return fields:

EMBER:
  pred_behavior
  true_behavior
  explanation

Big-Vul / Juliet:
  pred_cwe
  true_cwe
  explanation

MalwareBazaar:
  pred_behavior
  true_behavior
  explanation

Phoenix logging:
Tasks SHOULD log hallucination events via:
    from phoenix.trace import log_event

---

# 4. SCORER REQUIREMENTS

The following scorers MUST exist:

1. MalwareBehaviorScorer
2. VulnF1Scorer
3. ExplanationSimilarityScorer
4. HallucinationScorer

## 4.1 MalwareBehaviorScorer

Must:
- Compare pred_behavior to true_behavior
- Return numeric score ∈ [0,1]

## 4.2 VulnF1Scorer

Must:
- Compute precision
- Compute recall
- Compute F1
- Return scalar F1

## 4.3 ExplanationSimilarityScorer

Must:
- Compute semantic similarity
- Use BERTScore and ROUGE
- Return float ∈ [0,1]

## 4.4 HallucinationScorer

Must:
- Penalize outputs containing tokens not grounded in input
- Return score ∈ [0,1]
- Higher = less hallucination

---

# 5. YAML CONFIG REQUIREMENTS

Each config must include:

- name
- description
- loader
- task
- scorers list

The scorers list must include at least:
- primary task scorer
- explanation similarity scorer
- hallucination scorer

---

# 6. ANALYSIS MODULE REQUIREMENTS

analysis/run_analysis.py must:

1. Load CSV results
2. Compute:
   - Per-CWE F1 pivot table
   - Behavior confusion matrix
   - Time-series regression (model_version vs score)
3. Produce:
   - Heatmap
   - Confusion matrix
   - Line plot
4. Execute without manual editing

---

# 7. END-TO-END VALIDATION PROCEDURE

To verify correctness:

1. Run:
   inspect eval configs/bigvul.yaml

2. Confirm:
   - Results CSV created
   - Scores present
   - No missing ground truth fields

3. Run:
   python analysis/run_analysis.py

4. Confirm:
   - Plots render
   - No exceptions

---

# 8. FAILURE CONDITIONS

Implementation is invalid if:

- Any required scorer missing
- Tasks do not return structured outputs
- YAML configs malformed
- Analysis crashes on valid results
- Dataset loaders perform inference
- F1 not computed correctly

---

# 9. OPTIONAL ADVANCED CHECKS

LLM verifier may also check:

- Hallucination logs appear in Phoenix
- Explanation similarity correlates with F1
- No scorer mutates model outputs
- Deterministic behavior when seed fixed

---

END OF VERIFICATION SPEC