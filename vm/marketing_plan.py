"""Check plans for the marketing Python VM executor. Plans are trusted controller data,
never source-derived. The production plan is the fixed reviewed three-command battery;
qualification fixtures substitute controller-authored Python snippets with deliberately
failing or non-terminating behaviour. Reuses the ci_plan serialization so the guest
executor protocol stays identical to the qualified source-CI lane."""
from ci_util import validate_plan

FIXTURES = '/fixtures'

LIBRARY = {
    'marketing_manifest_validation': (120, '/ws/src', ['python3', 'scripts/validate.py']),
    'marketing_stdlib_tests': (900, '/ws/src',
        ['python3', '-m', 'unittest', 'discover', '-s', 'tests', '-v']),
    'marketing_compileall': (120, '/ws/src', ['python3', '-m', 'compileall', '-q', 'scripts', 'tests']),
    'fixture_deliberate_failure': (60, '/ws/src', ['python3', FIXTURES + '/exit-one.py']),
    'fixture_hold_timeout': (25, '/ws/src', ['python3', FIXTURES + '/hold.py']),
}

GUEST_NATIVE_CHECKS = ['c1_source_integrity', 'c2_toolchain_validation']

PRODUCTION_PLAN = [{'name': name, 'timeout_s': LIBRARY[name][0], 'cwd': LIBRARY[name][1],
                    'argv': list(LIBRARY[name][2])} for name in
                   ['marketing_manifest_validation', 'marketing_stdlib_tests',
                    'marketing_compileall']]

FIXTURE_PLANS = {
    'q2_deliberate_failure': [{'name': name, 'timeout_s': LIBRARY[name][0],
                               'cwd': LIBRARY[name][1], 'argv': list(LIBRARY[name][2])}
                              for name in ['fixture_deliberate_failure']],
    'q3_resource_timeout': [{'name': name, 'timeout_s': LIBRARY[name][0],
                             'cwd': LIBRARY[name][1], 'argv': list(LIBRARY[name][2])}
                            for name in ['fixture_hold_timeout']],
}
# Q4 (cancellation) uses the production plan with MODE=hold: the controller SIGTERMs
# the live VM after SRC_READY, so no separate fixture plan is required.


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
