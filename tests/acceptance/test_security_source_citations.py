"""Synthetic analyzer acceptance; no target code or providers execute."""

import copy
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from tests.run_dual_runtime_acceptance import security_verifier_post_schema_errors


SCRIPT = Path(__file__).resolve().parents[2] / 'security-toolkit/skills/security-vuln-analyzer/scripts/source-citations.py'
MODULE = runpy.run_path(str(SCRIPT))
CHECKS = runpy.run_path(str(SCRIPT.with_name('deterministic-check.py')))
PIN = 'a' * 40


def encode(value):
    return json.dumps(value, ensure_ascii=False).encode('utf-8')


class SourceCitationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = b'heading\r\n  let x = "\\\\"; // caf\xc3\xa9\r\nlast'
        (self.root / 'source.rs').write_bytes(self.source)
        self.registry = {'sources': [{'repository': 'example', 'revision': PIN, 'root': str(self.root),
            'files': [{'relative_path': 'source.rs', 'sha256': hashlib.sha256(self.source).hexdigest(),
                       'allowed_ranges': [[2, 3]]}]}]}
        self.citation = {'source_kind': 'repository', 'repository': 'example', 'revision': PIN,
                         'relative_path': 'source.rs', 'start_line': 2, 'end_line': 3,
                         'quote': '', 'observation': 'A role-authored interpretation.', 'artifact_id': ''}
        self.raw = {'status': 'COMPLETE', 'candidate_id': 'unchanged', 'judgment': 'INCONCLUSIVE',
                    'evidence': [self.citation], 'counterevidence': [], 'assumptions': ['preserve me']}

    def extract(self, raw=None, registry=None):
        registry_bytes = encode(self.registry if registry is None else registry)
        return MODULE['extract_citations'](encode(self.raw if raw is None else raw), registry_bytes,
                                            hashlib.sha256(registry_bytes).hexdigest())

    def test_exact_source_bytes_and_all_nonquotation_fields_survive(self):
        original = copy.deepcopy(self.raw)
        result = self.extract()
        expected = copy.deepcopy(original)
        expected['evidence'][0]['quote'] = self.source.split(b'\r\n', 1)[1].decode('utf-8')
        self.assertEqual(result['artifact'], expected)
        self.assertEqual(self.raw, original)
        self.assertEqual(result['provenance']['raw_artifact_sha256'], hashlib.sha256(encode(original)).hexdigest())
        self.assertEqual(result['provenance']['source_registry_sha256'], hashlib.sha256(encode(self.registry)).hexdigest())
        self.assertEqual(result['provenance']['derived_artifact_sha256'], hashlib.sha256(MODULE['canonical_bytes'](expected)).hexdigest())
        receipt = result['provenance']['citations'][0]
        self.assertEqual(receipt['json_pointer'], '/evidence/0')
        self.assertEqual(receipt['quote_sha256'], hashlib.sha256(expected['evidence'][0]['quote'].encode()).hexdigest())

    def test_raw_quotation_never_supplies_the_derived_evidence(self):
        self.raw['evidence'][0]['quote'] = 'Incorrect model-authored copy with missing backslashes.'
        result = self.extract()
        self.assertEqual(result['artifact']['evidence'][0]['quote'], self.source.split(b'\r\n', 1)[1].decode())
        self.assertEqual(self.raw['evidence'][0]['quote'], 'Incorrect model-authored copy with missing backslashes.')

    def test_nonrepository_citations_are_unchanged(self):
        other = {'source_kind': 'runtime_observation', 'quote': 'literal runtime value', 'artifact_id': 'frozen-event'}
        self.raw['counterevidence'].append(other)
        self.assertEqual(self.extract()['artifact']['counterevidence'], [other])

    def test_bad_references_fail_instead_of_being_repaired(self):
        for field, value in [('repository', 'other'), ('revision', 'b' * 40), ('relative_path', '../source.rs'),
                             ('relative_path', './source.rs'), ('relative_path', 'dir//source.rs'),
                             ('start_line', True), ('start_line', 0), ('start_line', 1), ('end_line', 4),
                             ('artifact_id', 'not-empty')]:
            with self.subTest(field=field, value=value):
                raw = copy.deepcopy(self.raw)
                raw['evidence'][0][field] = value
                with self.assertRaises(ValueError):
                    self.extract(raw)

    def test_changed_source_and_invalid_utf8_fail(self):
        (self.root / 'source.rs').write_bytes(b'changed source')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            self.extract()
        data = b'heading\n\xff\nlast'
        (self.root / 'source.rs').write_bytes(data)
        self.registry['sources'][0]['files'][0]['sha256'] = hashlib.sha256(data).hexdigest()
        with self.assertRaises(UnicodeError):
            self.extract()

    def test_symlink_escape_and_ambiguous_registry_fail(self):
        with tempfile.TemporaryDirectory() as outside:
            other = Path(outside) / 'source.rs'
            other.write_bytes(self.source)
            (self.root / 'source.rs').unlink()
            (self.root / 'source.rs').symlink_to(other)
            with self.assertRaisesRegex(ValueError, 'escapes'):
                self.extract()
        registry = copy.deepcopy(self.registry)
        registry['sources'].append(copy.deepcopy(registry['sources'][0]))
        with self.assertRaisesRegex(ValueError, 'duplicate source'):
            self.extract(registry=registry)

    def test_duplicate_json_fields_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            registry_bytes = encode(self.registry)
            MODULE['extract_citations'](b'{"evidence":[],"evidence":[]}', registry_bytes,
                                        hashlib.sha256(registry_bytes).hexdigest())

    def test_registry_is_bound_to_the_pre_dispatch_digest(self):
        original_digest = hashlib.sha256(encode(self.registry)).hexdigest()
        replacement = b'heading\nnew source\nlast'
        (self.root / 'source.rs').write_bytes(replacement)
        self.registry['sources'][0]['files'][0]['sha256'] = hashlib.sha256(replacement).hexdigest()
        with self.assertRaisesRegex(ValueError, 'pre-dispatch SHA-256'):
            MODULE['extract_citations'](encode(self.raw), encode(self.registry), original_digest)
        for invalid in (None, '', 'not-a-digest'):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, 'pre-dispatch registry digest'):
                MODULE['extract_citations'](encode(self.raw), encode(self.registry), invalid)

    def test_cli_preserves_raw_and_refuses_output_overwrite(self):
        raw, sources, output = [self.root / name for name in ('raw.json', 'sources.json', 'envelope.json')]
        raw.write_bytes(encode(self.raw))
        sources.write_bytes(encode(self.registry))
        argv = [sys.executable, str(SCRIPT), '--artifact', str(raw), '--sources', str(sources),
                '--expected-sources-sha256', hashlib.sha256(sources.read_bytes()).hexdigest(), '--output', str(output)]
        first = subprocess.run(argv, capture_output=True, text=True)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        saved = output.read_bytes()
        second = subprocess.run(argv, capture_output=True, text=True)
        self.assertEqual(second.returncode, 1, second.stdout + second.stderr)
        self.assertEqual(output.read_bytes(), saved)
        self.assertEqual(raw.read_bytes(), encode(self.raw))
        self.assertEqual(sources.read_bytes(), encode(self.registry))


class DeterministicCheckTest(unittest.TestCase):
    def test_physical_lines_ignore_unicode_and_control_separators(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / 'source.rs'
            for newline in (b'\n', b'\r\n', b'\r'):
                with self.subTest(newline=newline):
                    first = 'let s = "\u2028\u2029\u0085\v\f\x1c\x1d\x1e";'.encode()
                    source.write_bytes(first + newline + b'physical second' + newline + b'last')
                    self.assertEqual(CHECKS['normalized_line_slice'](source, 1, 1), first + b'\n')
                    self.assertEqual(CHECKS['normalized_line_slice'](source, 2, 2), b'physical second\n')
                    self.assertEqual(CHECKS['normalized_line_slice'](source, 3, 3), b'last')
                    with self.assertRaisesRegex(CHECKS['RequestError'], 'exceeds'):
                        CHECKS['normalized_line_slice'](source, 4, 4)
                    registry = {'sources': [{'repository': 'example', 'revision': PIN, 'root': str(root),
                        'files': [{'relative_path': 'source.rs', 'sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                                   'allowed_ranges': [[1, 3]]}]}]}
                    raw = {'evidence': [{'source_kind': 'repository', 'repository': 'example', 'revision': PIN,
                        'relative_path': 'source.rs', 'start_line': 2, 'end_line': 2, 'quote': '', 'artifact_id': ''}]}
                    registry_bytes = encode(registry)
                    extracted = MODULE['extract_citations'](encode(raw), registry_bytes, hashlib.sha256(registry_bytes).hexdigest())
                    self.assertEqual(extracted['artifact']['evidence'][0]['quote'].encode(), b'physical second' + newline)

    def test_windows_rejected_before_any_child_or_pipe_reader_starts(self):
        routing = [{'literal_result': 'PASSED', 'final_status': 'DISPUTED'}]
        proposition = 'The synthetic test observes its registered result.'
        request = {'packet_revision': 'fixture', 'candidate_id': 'fixture', 'proposition': proposition,
            'check_id': 'fixture', 'check_kind': 'FROZEN_TEST_REFERENCE', 'repository': 'example',
            'target_revision': PIN, 'routing_table': routing, 'registry_sha256': 'b' * 64, 'frozen_test_id': 'fixture'}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            registry = {'tests': {'fixture': {'repository': 'example', 'revision': PIN,
                'proposition_sha256': CHECKS['normalized_proposition_digest'](proposition), 'routing_table': routing,
                'argv': [sys.executable, '-c', 'print("safe")'], 'working_directory': '.', 'timeout_seconds': 1,
                'expected_exit_status': 0, 'environment': {}}}}
            result = CHECKS['base_result'](request, routing)
            function = CHECKS['run_frozen_test']
            with mock.patch.dict(function.__globals__, {'os': SimpleNamespace(name='nt')}), \
                    mock.patch.object(function.__globals__['subprocess'], 'Popen') as popen, \
                    mock.patch.object(function.__globals__['selectors'], 'DefaultSelector') as selector:
                function(request, root, registry, 'b' * 64, result)
            popen.assert_not_called()
            selector.assert_not_called()
            self.assertEqual(result['status'], 'FAILED')
            self.assertEqual(result['literal_check_result'], 'NOT_RUN')
            self.assertEqual(result['executed_argv'], [])
            self.assertIn('POSIX', result['bounded_output'])


class FixClosureTest(unittest.TestCase):
    def setUp(self):
        self.payload = {'role_type': 'verifier_stage2', 'status': 'COMPLETE',
            'verification_result': 'INCONCLUSIVE', 'affected_gates': ['mitigation_or_fix_state'],
            'evidence': [], 'counterevidence': [], 'remaining_assumptions': [],
            'uncertainty': ['Synthetic fixture; no target behavior was executed.'],
            'closure_recommendation': 'CONDITIONAL YES', 'closure_conditions': [{
                'residual_scope_or_uncertainty': 'Synthetic residual scope.',
                'tracking_reference': 'fixture-condition-1', 'owner': 'fixture owner',
                'acceptance_required': 'Human must accept the recorded residual.'}]}

    def test_conditional_closure_requires_tracked_nonblank_conditions(self):
        self.assertEqual(security_verifier_post_schema_errors(self.payload, fix_mode=True), [])
        for field in self.payload['closure_conditions'][0]:
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                payload['closure_conditions'][0][field] = ' \t\r\n\f\v'
                self.assertIn('closure condition has a blank field',
                              security_verifier_post_schema_errors(payload, fix_mode=True))
        self.payload['closure_conditions'] = []
        self.assertIn('conditional closure lacks a tracked condition',
                      security_verifier_post_schema_errors(self.payload, fix_mode=True))

    def test_unconditional_closure_cannot_hide_residual_conditions(self):
        self.payload['closure_recommendation'] = 'YES'
        self.assertIn('unconditional closure has residual conditions',
                      security_verifier_post_schema_errors(self.payload, fix_mode=True))
        self.payload['closure_conditions'] = []
        self.assertEqual(security_verifier_post_schema_errors(self.payload, fix_mode=True), [])

    def test_fix_conditions_do_not_replace_ordinary_verifier_checks(self):
        self.payload['verification_result'] = 'CONFIRMED'
        self.assertIn('confirmed stage 2 lacks supporting evidence',
                      security_verifier_post_schema_errors(self.payload, fix_mode=True))


if __name__ == '__main__':
    unittest.main()
