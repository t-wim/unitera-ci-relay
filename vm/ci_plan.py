"""Check plans for the source-CI executor. Plans are trusted controller data, never source-derived.

The guest executor receives each command as an exact argv (unit-separator fields) and exec's it
directly; it never evaluates a shell string. Command arguments are validated by ci_util.validate_plan.
"""
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


def plan_by_name(name):
    if name == 'production':
        return [dict(entry) for entry in PRODUCTION_PLAN]
    if name in FIXTURE_PLANS:
        return [dict(entry) for entry in FIXTURE_PLANS[name]]
    raise ValueError('unknown plan: ' + str(name))


def expected_check_set(plan_name):
    return set(GUEST_NATIVE_CHECKS) | {entry['name'] for entry in plan_by_name(plan_name)}


def serialize_plan(plan):
    """Render plan lines: name|timeout|cwd then unit-separator argv fields."""
    lines = []
    for entry in plan:
        fields = [entry['name'], str(entry['timeout_s']), entry['cwd']] + list(entry['argv'])
        lines.append('|'.join(fields[:3]) + '|' + '\x1f'.join(fields[3:]))
    return '\n'.join(lines) + '\n'


for _plan in [PRODUCTION_PLAN] + list(FIXTURE_PLANS.values()):
    validate_plan(_plan)
