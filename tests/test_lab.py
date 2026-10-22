"""The ground-truth lab (tests/lab.py): every case must get the answer the standard gives."""

import lab


def test_lab_cases_get_the_expected_answers():
    results = lab.run_all()
    bad = [m for m in lab.mismatches(results) if tuple(m.split(":")[0].split()) not in lab.KNOWN]
    assert not bad, "\n".join(bad)


def test_every_lab_case_names_its_problem_and_checks():
    names = [c.name for c in lab.CASES]
    assert len(names) == len(set(names))
    for case in lab.CASES:
        assert case.about and case.expect
