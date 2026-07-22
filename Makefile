.PHONY: setup env-report openssl-build openssl-report schemas catalog-check policy-check selector-check selector-nondegenerate-check policy-schemas crypto-material native-build crypto-smoke crypto-calibration crypto-calibration-validate crypto-calibration-analyze calibration-quality crypto-calibration-confirmatory calibration-compare paired-cost-analysis conflict-stage-check stage8-register stage8-run stage8-resume stage8-validate stage8-code-check stage7-check stage7-code-check stage6-code-check stage4b-code-check stage4a-code-check stage3d-code-check stage3c-code-check stage3b-code-check stage3a-check stage2-check models-check test lint typecheck check clean

PYTHON ?= python3
LOCAL_OPENSSL ?= .local/openssl-3.5.7/bin/openssl

setup:
	$(PYTHON) -m pip install -e ".[dev]"

env-report:
	$(PYTHON) scripts/check_environment.py

openssl-build:
	bash scripts/build_local_openssl.sh

openssl-report:
	$(PYTHON) scripts/check_environment.py --openssl-bin "$(LOCAL_OPENSSL)" --output-dir artifacts/environment

schemas:
	$(PYTHON) scripts/export_schemas.py

catalog-check:
	$(PYTHON) scripts/validate_profile_catalog.py

policy-check:
	$(PYTHON) scripts/validate_policy_stage.py

selector-check:
	$(PYTHON) scripts/validate_selector_stage.py

selector-nondegenerate-check:
	$(PYTHON) scripts/validate_selector_stage.py

policy-schemas:
	$(PYTHON) scripts/export_schemas.py

crypto-material:
	bash scripts/generate_lab_crypto_material.sh
	$(PYTHON) scripts/inspect_lab_crypto_material.py

native-build:
	bash scripts/build_native_benchmarks.sh

crypto-smoke:
	$(PYTHON) scripts/run_crypto_smoke.py

crypto-calibration:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required"; exit 2)
	$(PYTHON) scripts/run_crypto_calibration.py --run-id "$(RUN_ID)" $(if $(CPU_CORE),--cpu-core "$(CPU_CORE)",) $(if $(ALLOW_DIRTY),--allow-dirty,)

crypto-calibration-validate:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required"; exit 2)
	$(PYTHON) scripts/validate_crypto_calibration.py --run-id "$(RUN_ID)"

crypto-calibration-analyze:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required"; exit 2)
	$(PYTHON) scripts/analyze_crypto_calibration.py --run-id "$(RUN_ID)"

calibration-quality:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required"; exit 2)
	$(PYTHON) scripts/analyze_calibration_quality.py --run-id "$(RUN_ID)"

crypto-calibration-confirmatory:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required"; exit 2)
	@test -n "$(BASELINE_RUN_ID)" || (echo "BASELINE_RUN_ID is required"; exit 2)
	$(PYTHON) scripts/run_crypto_calibration.py --config configs/calibration/crypto_calibration_confirmatory.yaml --run-id "$(RUN_ID)" --reuse-cpu-from-run "$(BASELINE_RUN_ID)" $(if $(ALLOW_DIRTY),--allow-dirty,)

calibration-compare:
	@test -n "$(BASELINE_RUN_ID)" || (echo "BASELINE_RUN_ID is required"; exit 2)
	@test -n "$(CONFIRMATORY_RUN_ID)" || (echo "CONFIRMATORY_RUN_ID is required"; exit 2)
	$(PYTHON) scripts/compare_crypto_calibrations.py --baseline-run-id "$(BASELINE_RUN_ID)" --confirmatory-run-id "$(CONFIRMATORY_RUN_ID)" --output-dir "artifacts/calibration-comparison/$(BASELINE_RUN_ID)__$(CONFIRMATORY_RUN_ID)" $(if $(CREATE_COMBINED_SUMMARY),--create-combined-summary,)

paired-cost-analysis:
	@test -n "$(BASELINE_RUN_ID)" || (echo "BASELINE_RUN_ID is required"; exit 2)
	@test -n "$(CONFIRMATORY_RUN_ID)" || (echo "CONFIRMATORY_RUN_ID is required"; exit 2)
	$(PYTHON) scripts/analyze_paired_crypto_costs.py --baseline-run-id "$(BASELINE_RUN_ID)" --confirmatory-run-id "$(CONFIRMATORY_RUN_ID)" --output-dir "artifacts/paired-cost-calibration/$(BASELINE_RUN_ID)__$(CONFIRMATORY_RUN_ID)"

conflict-stage-check:
	$(PYTHON) scripts/validate_stage6.py

stage8-register:
	$(PYTHON) scripts/register_stage8_campaign.py

stage8-run:
	$(PYTHON) scripts/run_stage8_campaign.py $(if $(RUN_ID),--run-id "$(RUN_ID)",)

stage8-resume:
	$(PYTHON) scripts/resume_stage8_campaign.py $(if $(RUN_ID),--run-id "$(RUN_ID)",)

stage8-validate:
	@test -n "$(RUN_DIR)" || (echo "RUN_DIR is required"; exit 2)
	$(PYTHON) scripts/validate_stage8.py "$(RUN_DIR)"

stage8-code-check:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m pytest -q
	$(PYTHON) -m mypy src scripts

stage7-check:
	$(PYTHON) scripts/validate_stage7.py

stage7-code-check:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m pytest -q
	$(PYTHON) -m mypy src scripts

stage6-code-check:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m pytest -q
	$(PYTHON) -m mypy src scripts

stage3d-code-check:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m pytest -q
	$(PYTHON) -m mypy src scripts

stage4a-code-check:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m pytest -q
	$(PYTHON) -m mypy src scripts

stage4b-code-check:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m pytest -q
	$(PYTHON) -m mypy src scripts

stage3c-code-check:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m pytest -q
	$(PYTHON) -m mypy src scripts

stage3b-code-check:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m pytest -q
	$(PYTHON) -m mypy src scripts

stage3a-check: lint test typecheck crypto-material native-build crypto-smoke

stage2-check: policy-schemas catalog-check policy-check lint test typecheck

models-check: schemas catalog-check lint test typecheck

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .

typecheck:
	$(PYTHON) -m mypy

check: lint typecheck test

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov

# === Public artifact commands ===
.PHONY: artifact-setup artifact-data-check artifact-check

FINAL_STAGE8_RUN := runs/stage8/stage8-final-20260714-r2

artifact-setup:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.lock.txt
	$(PYTHON) -m pip install -e . --no-deps

artifact-data-check:
	$(PYTHON) scripts/validate_frozen_stage8_artifact.py
	$(PYTHON) scripts/validate_public_stage9_artifact.py

artifact-check: check artifact-data-check
	@echo "[PASS] Source code, tests, frozen campaign, and analysis bundle validated."

# === Paper reproduction commands ===
.PHONY: reproduce-paper

reproduce-paper: artifact-check
	$(PYTHON) scripts/reproduce_manipulability_audit.py
	$(PYTHON) scripts/reproduce_synthetic_catalog.py
	@echo "[PASS] The principal frozen and post-hoc paper results were reproduced."
