# Live tests against real AWS load balancers (see
# docs/testing/aws-alb-policy-fixtures.md). Everything else builds and tests
# with cargo, ruff and pytest directly.

TF_DIR         := infra/test-alb
CARGO_FEATURES ?= vendored
# The client allowed through the load balancer's security group.
ALLOWED_CIDR   ?= $(shell curl -sSf --max-time 10 https://checkip.amazonaws.com)/32
TF_VARS         = -var "region=$(AWS_REGION)" -var 'allowed_cidrs=["$(ALLOWED_CIDR)"]'

.PHONY: live-alb live-alb-up live-alb-test live-alb-down

## Apply the fixture, run the live tests, and always destroy the fixture.
live-alb:
	@test -n "$(AWS_REGION)" || { echo "set AWS_REGION"; exit 2; }
	@$(MAKE) --no-print-directory live-alb-up; up=$$?; \
	if [ $$up -eq 0 ]; then $(MAKE) --no-print-directory live-alb-test; status=$$?; else status=$$up; fi; \
	$(MAKE) --no-print-directory live-alb-down; exit $$status

live-alb-up:
	terraform -chdir=$(TF_DIR) init -input=false
	terraform -chdir=$(TF_DIR) apply -input=false -auto-approve $(TF_VARS)

## Wait until both listeners answer, then run tests/policy_alb_live.rs.
live-alb-test:
	@for output in tls13_1_3_pq_url tls13_1_2_res_pq_url; do \
		url=$$(terraform -chdir=$(TF_DIR) output -raw $$output); \
		for attempt in $$(seq 1 30); do \
			curl -sk --max-time 5 -o /dev/null "$$url" && break; \
			echo "waiting for $$url ($$attempt/30)"; sleep 10; \
		done; \
	done
	DCERT_LIVE_ALB_TLS13_1_3_PQ_URL="$$(terraform -chdir=$(TF_DIR) output -raw tls13_1_3_pq_url)" \
	DCERT_LIVE_ALB_TLS13_1_2_RES_PQ_URL="$$(terraform -chdir=$(TF_DIR) output -raw tls13_1_2_res_pq_url)" \
	cargo test --features $(CARGO_FEATURES) --test policy_alb_live -- --nocapture

live-alb-down:
	terraform -chdir=$(TF_DIR) destroy -input=false -auto-approve $(TF_VARS)
