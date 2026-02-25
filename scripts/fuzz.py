#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
from pathlib import Path


def clear_output_dir(out_dir: Path) -> None:
    out_dir = out_dir.resolve()
    if out_dir == Path("/"):
        raise RuntimeError("Refusing to clear root directory")

    out_dir.mkdir(parents=True, exist_ok=True)
    for child in out_dir.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def run(cmd: list[str], cwd: Path) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build and run AFL++ fuzzing for Flecs script harness"
    )
    parser.add_argument("duration_seconds", nargs="?", default="300")
    parser.add_argument("out_dir", nargs="?", default=str(Path.cwd() / "out"))
    parser.add_argument("workers", nargs="?", default="8")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    out_dir = Path(args.out_dir)
    image_tag = os.environ.get("IMAGE_TAG", "flecs-script-afl")

    clear_output_dir(out_dir)

    run(
        [
            "docker",
            "build",
            "-f",
            "Dockerfile.afl",
            "-t",
            image_tag,
            ".",
        ],
        cwd=repo_root,
    )
    run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{out_dir.resolve()}:/work/out",
            image_tag,
            "/work/scripts/run_afl_in_container.sh",
            args.duration_seconds,
            "/work/out",
            args.workers,
        ],
        cwd=repo_root,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
