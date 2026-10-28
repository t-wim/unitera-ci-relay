"""Check plans for the source-CI executor. Plans are trusted controller data, never source-derived.

The guest executor receives each command as an exact argv (unit-separator fields) and exec's it
directly; it never evaluates a shell string. Command arguments are validated by ci_util.validate_plan.

The baum-os governance plan executes the VERBATIM `run:` bodies of the governance job at the
pinned baum-os commit: each body travels as a digest-bound script file at /plan/<wf>/<job>/<n>.sh
and bash executes exactly that file (test_baum_profile.py asserts byte equality against the
W2-bound execution plan, so a body drift fails the battery before any VM boots).
"""
import re

from ci_util import validate_plan

FIXTURES = '/fixtures'

LIBRARY = {
    'c3_frozen_install': (1500, '/ws/src',
        ['node', '/pnpm/pnpm.cjs', 'install', '--frozen-lockfile', '--offline', '--store-dir', '/ws/store']),
    'c4_build_packages': (1800, '/ws/src',
        ['node', '/pnpm/pnpm.cjs', '-r', '--if-present', '--filter', './packages/*', 'run', 'build']),
    'c5_api_typecheck': (1200, '/ws/src',
        ['node', '/pnpm/pnpm.cjs', '--filter', './apps/api', 'exec', 'tsc', '--noEmit']),
    'c6_lint_ts': (1500, '/ws/src',
        ['node', '/pnpm/pnpm.cjs', '-r', '--if-present', 'run', 'lint']),
    'c7_api_unit_baseline': (3600, '/ws/src',
        ['node', '/pnpm/pnpm.cjs', '--filter', './apps/api', 'run', 'test:unit-baseline', '--',
         '--maxWorkers=2', '--reporter=dot']),
    'c8_governance_check': (1200, '/ws/src',
        ['node', '/pnpm/pnpm.cjs', 'run', 'governance:check']),
    'fixture_real_pnpm_failure': (120, '/ws/src',
        ['node', '/pnpm/pnpm.cjs', '--invalid-flag-for-failure-injection']),
    'fixture_exit_one': (60, '/ws/src', ['node', FIXTURES + '/exit-one.mjs']),
    'fixture_hold_timeout': (20, '/ws/src', ['node', FIXTURES + '/hold.mjs']),
}

GUEST_NATIVE_CHECKS = ['c1_source_integrity', 'c2_toolchain_validation']

PRODUCTION_ORDER = ['c3_frozen_install', 'c4_build_packages', 'c5_api_typecheck',
                    'c6_lint_ts', 'c7_api_unit_baseline', 'c8_governance_check']

PRODUCTION_PLAN = [{'name': name, 'timeout_s': LIBRARY[name][0], 'cwd': LIBRARY[name][1],
                    'argv': list(LIBRARY[name][2])} for name in PRODUCTION_ORDER]

FIXTURE_PLANS = {
    'q4_forced_build_failure': [{'name': name, 'timeout_s': LIBRARY[name][0], 'cwd': LIBRARY[name][1],
                                 'argv': list(LIBRARY[name][2])} for name in ['fixture_real_pnpm_failure']],
    'q5_forced_test_failure': [{'name': name, 'timeout_s': LIBRARY[name][0], 'cwd': LIBRARY[name][1],
                                'argv': list(LIBRARY[name][2])} for name in ['fixture_exit_one']],
    'q7_resource_timeout': [{'name': name, 'timeout_s': LIBRARY[name][0], 'cwd': LIBRARY[name][1],
                             'argv': list(LIBRARY[name][2])} for name in ['fixture_hold_timeout']],
}

SCRIPT_PATH_RE = re.compile(r'/plan/[a-z0-9-]+\.yml/[a-z0-9_-]+/[0-9]+\.sh')
BAUM_SCRIPT_BASE = '/plan/governance-guardrails.yml/governance/'

# Verbatim run-step bodies of .github/workflows/governance-guardrails.yml, job governance,
# steps 4-8 at baum-os d8f96217b121325ef1f4d46a8c3e5743e31fc0cb (run_sha256 in comments;
# test_baum_profile re-derives them from the W2-bound execution plan).
BAUM_GOV = {
    'g4_node24': (60, BAUM_SCRIPT_BASE + '4.sh',
        # run_sha256 d96c7df03e884ab303f50dd271a95d23f589691b304e019fe251ae6640583c1e
        'node -e "const major = process.versions.node.split(\'.\')[0]; if (major !== \'24\') '
        '{ console.error(\'Expected Node 24.x, got \' + process.version); process.exit(1); }"\n'),
    'g5_frozen_install': (1500, BAUM_SCRIPT_BASE + '5.sh',
        # run_sha256 f733afb2da73a36bd48778fd7502436e384741ad191367d97182afc4909130a5
        'pnpm install --frozen-lockfile'),
    'g6_tracked_artifacts': (300, BAUM_SCRIPT_BASE + '6.sh',
        # run_sha256 4f0492754b31859ad02e7200edfadc4f2543fd1d160c12a7dd5688994a9fdbe2
        'TRACKED=$(git ls-files | grep -E \'(^|/)(\\.next|dist|build|coverage|out)(/|$)\' || true)\n'
        'if [ -n "$TRACKED" ]; then\n'
        '  echo "::error::Tracked generated artifacts found."\n'
        '  echo "$TRACKED"\n'
        '  exit 1\n'
        'fi\n'),
    'g7_context_pack': (1500, BAUM_SCRIPT_BASE + '7.sh',
        # run_sha256 0aa8d6f53a60c8a1d999baa40eb8550515924b8510e293287035551dbcb4dd25
        'set -euo pipefail\n'
        'BUILD_OUTPUT=$(pnpm --silent context:pack README.md architecture.md operating_rules.md)\n'
        'echo "$BUILD_OUTPUT"\n'
        'PACK_DIR=$(printf \'%s\\n\' "$BUILD_OUTPUT" | sed -n \'s/^  Output:  //p\')\n'
        'if [ -z "$PACK_DIR" ]; then\n'
        '  echo "::error::Could not determine context pack output directory."\n'
        '  exit 1\n'
        'fi\n'
        'pnpm --silent context:validate "$PACK_DIR"\n'),
    'g8_orchestration': (2700, BAUM_SCRIPT_BASE + '8.sh',
        # run_sha256 be3af1046082ce9df8b86d706d0c6fd1fa282bf9ad6b82fa3232ae60b8751090
        'pnpm validate:orchestration'),
}
BAUM_GOV_ORDER = ['g4_node24', 'g5_frozen_install', 'g6_tracked_artifacts',
                  'g7_context_pack', 'g8_orchestration']

BAUM_PLAN = [{'name': name, 'timeout_s': BAUM_GOV[name][0], 'cwd': '/ws/src',
              'argv': ['bash', '-e', BAUM_GOV[name][1]], 'script': BAUM_GOV[name][2],
              'script_path': BAUM_GOV[name][1]} for name in BAUM_GOV_ORDER]

BAUM_GUEST_NATIVE_CHECKS = ['c1_source_integrity', 'c2_toolchain_validation',
                            'c1b_git_tree_identity']


def validate_script_entries(plan):
    for entry in plan:
        script = entry.get('script')
        path = entry.get('script_path')
        if not isinstance(script, str) or not script or len(script) > 8192 or '\0' in script:
            raise ValueError('plan script rejected: ' + entry['name'])
        if not isinstance(path, str) or not SCRIPT_PATH_RE.fullmatch(path):
            raise ValueError('plan script path rejected: ' + entry['name'] + ' ' + repr(path))
        if entry['argv'][0] != 'bash' or entry['argv'][-1] != path:
            raise ValueError('plan argv must execute exactly the pinned script: ' + entry['name'])
    return True


def guest_native_checks(plan_name):
    if str(plan_name).startswith('baum'):
        return list(BAUM_GUEST_NATIVE_CHECKS)
    return list(GUEST_NATIVE_CHECKS)


def plan_by_name(name):
    if name == 'production':
        return [dict(entry) for entry in PRODUCTION_PLAN]
    if name == 'baum_governance':
        return [dict(entry) for entry in BAUM_PLAN]
    if name in FIXTURE_PLANS:
        return [dict(entry) for entry in FIXTURE_PLANS[name]]
    raise ValueError('unknown plan: ' + str(name))


def expected_check_set(plan_name):
    return set(guest_native_checks(plan_name)) | {entry['name'] for entry in plan_by_name(plan_name)}


def serialize_plan(plan):
    """Render plan lines: name|timeout|cwd then unit-separator argv fields."""
    lines = []
    for entry in plan:
        fields = [entry['name'], str(entry['timeout_s']), entry['cwd']] + list(entry['argv'])
        lines.append('|'.join(fields[:3]) + '|' + '\x1f'.join(fields[3:]))
    return '\n'.join(lines) + '\n'


for _plan in [PRODUCTION_PLAN] + list(FIXTURE_PLANS.values()):
    validate_plan(_plan)
validate_plan(BAUM_PLAN)
validate_script_entries(BAUM_PLAN)
