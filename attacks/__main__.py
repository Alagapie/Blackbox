"""Run one attack from the command line:  python -m attacks rewrite_stolen_key"""
import sys

from attacks.attacks import ATTACKS, AttackError, run_attack

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ATTACKS:
        print("usage: python -m attacks <" + "|".join(ATTACKS) + ">")
        sys.exit(1)
    try:
        print(run_attack(sys.argv[1]))
    except AttackError as e:
        print("attack not possible:", e)
        sys.exit(1)
