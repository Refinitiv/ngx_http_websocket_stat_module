.PHONY: test test_e2e

test:
	docker compose build test && docker compose run --rm test
	docker compose down -t 0

test_e2e:
	docker compose build test_e2e && docker compose run --rm test_e2e
	docker compose down -t 0
