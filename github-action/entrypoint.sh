#!/bin/bash
set -x
files=$(eval "${INPUT_DIFF}")
(
for f in $files; do
    detect-pii -v 2 -f "${f}"
done
) | reviewdog -efm="%f:%l:%c: %m" -name="detect-pii" -reporter="${INPUT_REPORTER:-github-check}" -level="${INPUT_LEVEL}" -diff="${INPUT_DIFF}"


