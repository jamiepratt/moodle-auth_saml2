#!/usr/bin/env bash

set -euo pipefail

plugin_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workflow="$plugin_root/.github/workflows/ci.yml"

if grep -Fq 'moodle-plugin-ci phpunit' "$workflow"; then
    echo 'ci_workflow_contract_test: unsupported moodle-plugin-ci PHPUnit invocation' >&2
    exit 1
fi

grep -Fq 'bash plugin/tests/ci_workflow_contract_test.sh' "$workflow"
grep -Fq 'working-directory: moodle' "$workflow"
grep -Fq 'vendor/bin/phpunit --testsuite auth_saml2_testsuite' "$workflow"

for option in \
    --fail-on-warning \
    --fail-on-risky \
    --fail-on-incomplete \
    --fail-on-skipped \
    --fail-on-deprecation \
    --fail-on-phpunit-deprecation; do
    grep -Fq -- "$option" "$workflow"
done

echo 'ci_workflow_contract_test: PASS'
