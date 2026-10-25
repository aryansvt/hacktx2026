# scripts

Dev and ops helpers: mock event generators, seeding, deploy helpers.

- `mock_events.py`: pushes fake public events into redis so the frontend has something to show.
- `llm_misses.py`: reads the trap's llm call log (`/state/llm.jsonl`) and lists the commands that went to the llm most often, with outcomes and latency. The top of that list is what the rules engine should learn next.
- `llm_probe.py`: one real call to the trap's LLM with the prompt it builds for `git status`, printing warm-up time, call latency, tokens and the parsed reply. On the trap box: `docker compose -f infra/trap/docker-compose.yml exec -T trap python - < scripts/llm_probe.py` (add `--mode schema` or `--repeat 3`). Each call is one small Haiku request.
