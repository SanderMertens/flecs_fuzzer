# Flecs Script AFL Fuzzing

This repository contains an AFL++ harness for fuzzing Flecs script parsing and
evaluation.

## Prerequisites
Make sure the following prerequisites are installed:

- python3
- docker
- bake

## Usage
To run the fuzzer for 5 minutes, run the following command:

```
./scripts/fuzz.sh
```

To run the fuzzer for a custom amount of time, add the number of seconds as argument/:

```
./scripts/fuzz.sh 3000
```

Results of the fuzzer will be written to `out`.

## Reporting
After or during a fuzzing run, you can generate stack traces for each of the found crashes with:

```
./scripts/stack_traces.py
```

After that script finishes, run the following script to generate an HTML report of the crashes:

```
./scripts/html_report.py
```

If you run the HTML report script without the stack traces script, the generated HTML page will still show the found crashes, but without the stack trace.

## Testing
To generate test cases from the found crashes, run:

```
./scripts/generate_tests.py
```

This will generate a new test case for the script/Fuzzing test suite in the linked flecs repository. 

To reproduce the issues found by the fuzzer, run the following commands:

```
docker build -f Dockerfile.repro -t flecs-repro .
docker run --rm flecs-repro bash -lc "cd /work/flecs && bake run test/script -- Fuzzing -j 12"
```

This runs the tests in the same kind of environment that the fuzzer runs in.

Alternatively this command can be used to run the tests with asan:

```
docker run --rm flecs-repro bash -lc "cd /work/flecs && bake run test/script --cfg sanitize -- Fuzzing -j 12"
```
