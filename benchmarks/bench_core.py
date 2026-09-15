import argparse
import statistics
import time

from authz_analyzer import compile_expression, parse


def expressions(size: int) -> dict[str, str]:
    atoms = [f"x{index}" for index in range(size)]
    return {
        "or": " | ".join(atoms),
        "overlapping_dnf": " | ".join(f"({atom} & shared)" for atom in atoms),
        "parity": " ^ ".join(atoms),
    }


def measure(source: str, rounds: int) -> tuple[float, int]:
    timings = []
    node_count = 0
    for _ in range(rounds):
        started = time.perf_counter()
        bdd, _ = compile_expression(parse(source))
        timings.append(time.perf_counter() - started)
        node_count = bdd.node_count
    return statistics.median(timings) * 1_000, node_count


def main() -> None:
    parser = argparse.ArgumentParser(description="Smoke benchmark the Boolean core")
    parser.add_argument("--size", type=int, default=100)
    parser.add_argument("--rounds", type=int, default=10)
    args = parser.parse_args()
    if args.size < 1 or args.rounds < 1:
        parser.error("--size and --rounds must be positive")

    for name, source in expressions(args.size).items():
        elapsed_ms, nodes = measure(source, args.rounds)
        print(f"{name:16} {elapsed_ms:9.3f} ms  {nodes:7} BDD nodes")


if __name__ == "__main__":
    main()
