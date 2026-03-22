# CryptoFix

Automated detection and repair of Python cryptographic API misuse using dependency-guided LLM prompting.

## Overview

CryptoFix detects and auto-repairs 6 categories of cryptographic misuse in Python code:
- **R1**: Weak symmetric ciphers (DES, 3DES, RC4)
- **R3**: Weak hash functions (MD5, SHA1) in security contexts
- **R4**: Insecure block cipher modes (ECB)
- **R5**: Hardcoded cryptographic keys
- **R8**: Static IVs
- **R10**: Insufficient PBKDF2 iteration counts

## Setup
```bash
pip install groq requests
cp src/config.py.example src/config.py
# Add your API keys to src/config.py
```

## Usage
```bash
# Run detector on a directory
python -c "from src.detector import MisuseDetector; d=MisuseDetector(); print(d.analyze_file('yourfile.py'))"

# Run full experiment
python -c "from src.experiment import ExperimentRunner; r=ExperimentRunner(); r.run_on_directory('data/github_expanded'); r.print_summary()"

# Run ablation study
python -c "from src.ablation import run_ablation; run_ablation('data/github_expanded', max_files=60)"
```

## Results

| Metric | Value |
|--------|-------|
| Dataset | 128 Python files from GitHub |
| Misuses detected | 166 |
| Detector precision | 66.9% |
| Patch success rate | 62.3% |

### Ablation Study (prompt conditions × model size)

| Condition | Llama-3.1-8B | Llama-3.3-70B |
|-----------|-------------|---------------|
| A: Zero-shot | 12.8% | 33.3% |
| B: Rules only | 51.3% | 52.4% |
| C: Full CryptoFix (rules + dependency context) | 59.0% | 69.0% |

## Project Structure
```
src/
  detector.py       # AST-based misuse detector
  patcher.py        # LLM patch generator + validator
  experiment.py     # Batch experiment runner
  ablation.py       # Ablation study runner
  annotator.py      # Ground truth annotation CLI
  github_collector.py # Dataset collection
  rules.py          # Misuse rule definitions
results/            # All experimental results (JSON)
data/vulnerable/    # Synthetic test files
```

## Citation

Manuscript in preparation. Target venue: MSR / ISSTA 2026.
