# Testing with Deno
## Run tests
`TEST=1 deno test -A`

### Helpful flags
  - `--quiet`: reduce output to only show test/step name and result
  - `--parallel`: run tests in parallel
  - `--fail-fast[=N]`: halt after N errors (default N=1)
  - `--watch`: run tests automatically on each file change

## Coverage Report
Generate the test coverage profile:
```
  $ TEST=1 deno test -A --coverage=tests/coverage/cov_profile
```

then print the report to stdout
```
  $ deno coverage tests/coverage/cov_profile
```

or output as an lcov file
```
  $ deno coverage --lcov --output=tests/coverage/cov.lcov tests/coverage/cov_profile/
```
and parse the lcov file as a html folder, viewable in the browser
```
  $ genhtml -o tests/coverage/html_cov tests/coverage/cov.lcov
```
\
You may need to install lcov (e.g. `choco install lcov` on windows) and run the previous command using
```
  $ perl /c/ProgramData/chocolatey/lib/lcov/tools/bin/genhtml -o tests/coverage html_cov tests/coverage/cov.lcov
```
instead.
