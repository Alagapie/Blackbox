"""Run one scenario from the command line (ledger must be running).

    python -m agent pressure
"""
import sys

from agent.scenarios import SCENARIOS, run_scenario

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in SCENARIOS:
        print("usage: python -m agent <" + "|".join(SCENARIOS) + ">")
        sys.exit(1)
    print("session:", run_scenario(sys.argv[1]))
