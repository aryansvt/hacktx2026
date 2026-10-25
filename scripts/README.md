# scripts

Dev and ops helpers: mock event generators, seeding, deploy helpers.

- `mock_events.py`: pushes fake public events into redis so the frontend has something to show.
- `llm_misses.py`: reads the trap's llm call log (`/state/llm.jsonl`) and lists the commands that went to the llm most often, with outcomes and latency. The top of that list is what the rules engine should learn next.
