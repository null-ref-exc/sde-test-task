"""Локальные HTTP E2E без сторонних Python-пакетов и без подмен приложения."""
import concurrent.futures
import argparse
import datetime as dt
from email.utils import parsedate_to_datetime
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import unittest
import urllib.error
import urllib.request
import uuid

PROJECT = Path(__file__).resolve().parents[1]
DLL = PROJECT / 'src/VulnerabilityTracker.Api/bin/Release/net10.0/VulnerabilityTracker.Api.dll'
LOGS = Path(__file__).resolve().parent / 'logs'
URL = 'https://nonexistent.invalid/team/repo'
DOCKER_IMAGE = None


def parallel(action, count=24):
    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
        return list(pool.map(action, range(count)))


class Server:
    def __init__(self, name, duration=150, workers=2, capacity=100, environment='Production'):
        self.name, self.duration, self.workers, self.capacity = name, duration, workers, capacity
        self.environment = environment
        self.process = None

    def start(self):
        # Порт выбирается ОС; готовность проверяется по HTTP, а не фиксированной задержкой.
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.base = f'http://127.0.0.1:{port}'
        LOGS.mkdir(parents=True, exist_ok=True)
        self.log = (LOGS / f'{self.name}.log').open('ab')
        env = dict(os.environ, ASPNETCORE_URLS=self.base,
                   ASPNETCORE_ENVIRONMENT=self.environment, DOTNET_ENVIRONMENT=self.environment,
                   Scanning__DemoDurationMilliseconds=str(self.duration),
                   Scanning__MaxParallelScans=str(self.workers), Scanning__QueueCapacity=str(self.capacity))
        self.process = subprocess.Popen(['dotnet', str(DLL)], cwd=DLL.parent, env=env,
                                        stdout=self.log, stderr=subprocess.STDOUT,
                                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        try:
            return self.wait_ready()
        except BaseException:
            self.stop()
            raise

    def wait_ready(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process is not None and self.process.poll() is not None:
                raise RuntimeError(f'API exited; see {self.name}.log')
            try:
                # Проверяем маршрут API и доступ к БД без создания данных.
                # Пустого GUID в хранилище быть не может; документация для готовности не нужна.
                code, headers, body = self.request(
                    'GET', '/api/vulnerabilities/00000000-0000-0000-0000-000000000000')
                if (code == 404 and 'application/problem+json' in headers.get('Content-Type', '')
                        and isinstance(body, dict) and body.get('status') == 404
                        and body.get('title') == 'Not found' and body.get('traceId')):
                    return self
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(.05)
        raise TimeoutError(f'API startup timed out; see {self.name}.log')

    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=10)
            self.log.close()
            self.process = None

    def request(self, method, path, body=None, raw=None, content_type='application/json'):
        data = raw.encode() if raw is not None else json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method,
                                         headers={'Content-Type': content_type})
        try:
            response = urllib.request.urlopen(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            text = response.read().decode()
            content_type = response.headers.get('Content-Type', '').split(';')[0].strip()
            value = json.loads(text) if text and (content_type == 'application/json' or content_type.endswith('+json')) else text or None
            return response.status, response.headers, value

    def wait(self, scan_id, statuses=('Completed',), timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            code, _, state = self.request('GET', f'/api/scans/{scan_id}')
            if code != 200:
                raise AssertionError((code, state))
            if state['status'] in statuses:
                return state
            if state['status'] in ('Failed', 'Cancelled', 'Completed'):
                raise AssertionError(f'Unexpected terminal state: {state}')
            time.sleep(.02)
        raise TimeoutError(f'Scan {scan_id}: {state}')


class DockerServer(Server):
    def start(self):
        # Docker назначает свободный порт сам. Уникальное имя ограничивает очистку нашим контейнером.
        self.container = 'vulnerability-tracker-e2e-' + uuid.uuid4().hex
        LOGS.mkdir(parents=True, exist_ok=True)
        self.log = (LOGS / f'{self.name}.log').open('ab')
        try:
            subprocess.run([
                'docker', 'run', '-d', '--name', self.container,
                '-p', '127.0.0.1::8080',
                '-e', f'ASPNETCORE_ENVIRONMENT={self.environment}',
                '-e', f'DOTNET_ENVIRONMENT={self.environment}',
                '-e', f'Scanning__DemoDurationMilliseconds={self.duration}',
                '-e', f'Scanning__MaxParallelScans={self.workers}',
                '-e', f'Scanning__QueueCapacity={self.capacity}', DOCKER_IMAGE
            ], check=True, stdout=self.log, stderr=self.log, timeout=60)
            address = subprocess.check_output(
                ['docker', 'port', self.container, '8080/tcp'], text=True, timeout=15).strip()
            self.base = 'http://' + address
            return self.wait_ready()
        except BaseException:
            self.stop()
            raise

    def stop(self):
        container = getattr(self, 'container', None)
        if container is None:
            return
        try:
            # Сначала штатно останавливаем процесс, затем собираем в том числе shutdown-логи.
            try:
                subprocess.run(['docker', 'stop', '-t', '10', container],
                               stdout=self.log, stderr=self.log, timeout=20, check=True)
            finally:
                try:
                    subprocess.run(['docker', 'logs', container], stdout=self.log,
                                   stderr=self.log, timeout=15, check=True)
                finally:
                    subprocess.run(['docker', 'rm', '-f', container], stdout=self.log,
                                   stderr=self.log, timeout=15, check=True)
        finally:
            self.container = None
            self.log.close()


class HttpTests(unittest.TestCase):
    duration, workers, capacity = 150, 2, 100
    environment = 'Production'

    def setUp(self):
        server_type = DockerServer if DOCKER_IMAGE else Server
        self.api = server_type(self.id().split('.')[-1], self.duration, self.workers,
                               self.capacity, self.environment).start()
        self.addCleanup(self.api.stop)

    def expect(self, method, path, status, body=None, **kwargs):
        code, headers, value = self.api.request(method, path, body, **kwargs)
        self.assertEqual(status, code, value)
        if status >= 400:
            self.assertIn('application/problem+json', headers.get('Content-Type', ''))
            self.assertEqual(status, value['status'])
            self.assertTrue(value['traceId'])
        return headers, value

    def create(self, title='SQL injection', severity='High'):
        headers, value = self.expect('POST', '/api/vulnerabilities', 201, dict(title=title, severity=severity))
        self.assertEqual(7, uuid.UUID(value['id']).version)
        self.assertTrue(headers['Location'].endswith('/api/vulnerabilities/' + value['id']))
        # Date и createdAt используют часы сервера. Date округлён до секунды и кэшируется.
        # Часы Docker VM и хоста могут немного расходиться.
        created_at = dt.datetime.fromisoformat(value['createdAt'])
        self.assertEqual(dt.timedelta(0), created_at.utcoffset())
        self.assertLessEqual(abs((created_at - parsedate_to_datetime(headers['Date'])).total_seconds()), 2)
        return value

    def start_scan(self, url=URL):
        headers, value = self.expect('POST', '/api/scans', 202, dict(repositoryUrl=url))
        self.assertEqual(7, uuid.UUID(value['id']).version)
        self.assertEqual('Queued', value['status'])
        self.assertEqual({'id', 'repositoryUrl', 'status', 'createdAt'}, set(value))
        self.assertTrue(headers['Location'].endswith('/api/scans/' + value['id']))
        return value

    def cancel(self, scan_id):
        return self.expect('POST', f'/api/scans/{scan_id}/cancel', 200)[1]


class ContractTests(HttpTests):
    def test_title_trimming_precedes_length_validation(self):
        title = 'x' * 200
        self.assertEqual(title, self.create('  ' + title + '  ')['title'])
        self.expect('POST', '/api/vulnerabilities', 400,
                    dict(title=' ' + title + 'x ', severity='High'))

    def test_url_normalization_and_length_boundary(self):
        for supplied, expected in [('HTTPS://EXAMPLE.INVALID', 'https://example.invalid/'),
                                   ('http://example.invalid:80/repo', 'http://example.invalid/repo')]:
            with self.subTest(url=supplied):
                scan = self.start_scan(supplied)
                self.assertEqual(expected, scan['repositoryUrl'])
                self.assertEqual(expected, self.api.wait(scan['id'])['repositoryUrl'])
        prefix = 'https://example.invalid/'
        self.api.wait(self.start_scan(prefix + 'x' * (2048 - len(prefix)))['id'])
        # Нормализация Unicode в escaped URL тоже не должна превышать лимит.
        self.expect('POST', '/api/scans', 400, dict(repositoryUrl=prefix + '\u044f' * 500))

    def test_validation_errors_do_not_break_following_requests(self):
        for _ in range(5):
            self.expect('POST', '/api/vulnerabilities', 400, dict(title='', severity='High'))
            self.expect('POST', '/api/scans', 400, dict(repositoryUrl='invalid'))
            vulnerability = self.create()
            self.assertEqual(vulnerability, self.expect('GET', '/api/vulnerabilities/' + vulnerability['id'], 200)[1])
        state = self.api.wait(self.start_scan()['id'])
        self.assertTrue(state['result']['findings'])

    def test_create_read_severities_boundaries_and_duplicates(self):
        for severity in ('Low', 'Medium', 'High', 'Critical'):
            for title in ('x', 'Я' * 200, '  SQL injection  '):
                with self.subTest(severity=severity, title_length=len(title)):
                    created = self.create(title, severity)
                    self.assertEqual(title.strip(), created['title'])
                    self.assertEqual(severity, created['severity'])
                    self.assertEqual(created, self.expect('GET', '/api/vulnerabilities/' + created['id'], 200)[1])
        self.assertNotEqual(self.create()['id'], self.create()['id'])

    def test_invalid_vulnerability_bodies(self):
        bodies = [{}, {'title': 'x'}, {'severity': 'High'},
                  *[dict(title=t, severity='High') for t in (None, '', ' \t ', '\0', '\0abc', 'abc\0def', 'abc\0', 'x' * 201, 12, [])],
                  *[dict(title='x', severity=s) for s in (None, 'Unknown', 0, 2, 99, '2', [], {})]]
        for body in bodies:
            with self.subTest(body=body):
                self.expect('POST', '/api/vulnerabilities', 400, body)

    def test_invalid_scan_bodies(self):
        for body in [{}, *[dict(repositoryUrl=u) for u in (None, '', ' ', 'repo', '/relative',
                     'ftp://host/repo', 'file:///repo', 'https://', 'https://host/' + 'x' * 2048, 1, [])]]:
            with self.subTest(body=body):
                self.expect('POST', '/api/scans', 400, body)

    def test_malformed_json_null_empty_and_wrong_content_type(self):
        for path in ('/api/scans', '/api/vulnerabilities'):
            for raw in ('{', 'null', '', '[]', '42'):
                with self.subTest(path=path, raw=raw):
                    self.expect('POST', path, 400, raw=raw)
            self.expect('POST', path, 415, raw='{}', content_type='text/plain')

    def test_missing_resources_routes_and_methods(self):
        for identifier in (str(uuid.uuid4()), str(uuid.UUID(int=0)), 'not-a-guid'):
            for path in (f'/api/scans/{identifier}', f'/api/vulnerabilities/{identifier}'):
                with self.subTest(path=path):
                    self.expect('GET', path, 404)
            self.expect('POST', f'/api/scans/{identifier}/cancel', 404)
        self.expect('GET', '/missing', 404)
        self.expect('DELETE', '/api/scans/' + str(uuid.uuid4()), 405)

    def test_production_does_not_expose_documentation(self):
        for path in ('/openapi/v1.json', '/swagger', '/swagger/index.html', '/swagger/swagger-ui-bundle.js'):
            with self.subTest(path=path):
                self.expect('GET', path, 404)

    def test_parallel_creates_and_reads_are_independent(self):
        results = parallel(lambda _: self.create('Same title'))
        self.assertEqual(len(results), len({v['id'] for v in results}))
        reads = parallel(lambda i: self.expect('GET', '/api/vulnerabilities/' + results[i]['id'], 200)[1])
        self.assertEqual(results, reads)


class DocumentationTests(HttpTests):
    environment = 'Development'

    def test_openapi_contains_operations_and_inline_documentation(self):
        _, document = self.expect('GET', '/openapi/v1.json', 200)
        operations = [(path, method, operation) for path, methods in document['paths'].items()
                      for method, operation in methods.items() if method in ('get', 'post')]
        self.assertEqual(5, len(operations))
        for path, method, operation in operations:
            with self.subTest(path=path, method=method):
                self.assertTrue(operation['summary'])
                self.assertTrue(operation['description'])
                self.assertIn('500', operation['responses'])

    def test_swagger_ui_and_its_configuration_are_available(self):
        headers, html = self.expect('GET', '/swagger/index.html', 200)
        self.assertIn('text/html', headers['Content-Type'])
        self.assertIn('Swagger UI', html)

        _, configuration = self.expect('GET', '/swagger/index.js', 200)
        self.assertIn('/openapi/v1.json', configuration)

        _, bundle = self.expect('GET', '/swagger/swagger-ui-bundle.js', 200)
        self.assertTrue(bundle)


class ScanTests(HttpTests):
    def test_concurrent_cancellation_of_completed_scan_never_changes_result(self):
        self.create()
        scan = self.start_scan()
        snapshot = self.api.wait(scan['id'])
        answers = parallel(lambda _: self.cancel(scan['id']), 32)
        self.assertTrue(all(not a['success'] and a['status'] == 'Completed' for a in answers))
        self.assertEqual({snapshot['updatedAt']}, {a['updatedAt'] for a in answers})
        self.assertEqual(snapshot, self.expect('GET', '/api/scans/' + scan['id'], 200)[1])

    def test_saved_result_is_stable_after_catalog_changes(self):
        original = self.create('Original')
        scan = self.start_scan()
        state = self.api.wait(scan['id'])
        self.assertEqual(original, state['result']['findings'][0]['vulnerability'])
        parallel(lambda i: self.create(f'Later {i}'), 8)
        responses = parallel(lambda _: self.expect('GET', '/api/scans/' + scan['id'], 200)[1])
        self.assertTrue(all(response == state for response in responses))

    def test_mixed_parallel_creation_scanning_reading_and_cancellation(self):
        self.create('Seed')

        def workflow(index):
            vulnerability = self.create(f'Mixed {index}')
            scan = self.start_scan()
            self.assertEqual(vulnerability, self.expect('GET', '/api/vulnerabilities/' + vulnerability['id'], 200)[1])
            if index % 2 == 0:
                self.cancel(scan['id'])
            state = self.api.wait(scan['id'], ('Completed', 'Cancelled'))
            self.assertIsNone(state['error'])
            if state['status'] == 'Cancelled':
                self.assertIsNone(state['result'])
            else:
                self.assertTrue(state['result']['findings'])
            self.assertFalse(self.cancel(scan['id'])['success'])
            return scan['id']

        ids = parallel(workflow)
        self.assertEqual(24, len(set(ids)))
        self.api.wait(self.start_scan()['id'])

    def test_empty_tracker_and_completed_cancellation(self):
        for url in (URL, 'http://nonexistent.invalid/repo'):
            scan = self.start_scan(url)
            state = self.api.wait(scan['id'])
            self.assertEqual({'findings': []}, state['result'])
            self.assertIsNone(state['error'])
            cancel = self.cancel(scan['id'])
            self.assertFalse(cancel['success'])
            self.assertEqual('Completed', cancel['status'])
            self.assertEqual(state, self.expect('GET', '/api/scans/' + scan['id'], 200)[1])

    def test_random_findings_reference_catalog_and_valid_locations(self):
        catalog = [self.create(f'Finding {i}', ('Low', 'Medium', 'High', 'Critical')[i % 4]) for i in range(12)]
        by_id = {v['id']: v for v in catalog}
        ordered = sorted(by_id)
        scans = parallel(lambda _: self.start_scan(), 12)
        self.assertEqual(12, len({s['id'] for s in scans}))
        for scan in scans:
            state = self.api.wait(scan['id'])
            findings = state['result']['findings']
            self.assertEqual({'findings'}, set(state['result']))
            self.assertTrue(1 <= len(findings) <= len(catalog))
            ids = [f['vulnerability']['id'] for f in findings]
            offset = ordered.index(ids[0])
            self.assertEqual(ordered[offset:offset + len(ids)], ids)
            self.assertIsNone(state['error'])
            self.assertLessEqual(dt.datetime.fromisoformat(state['createdAt']), dt.datetime.fromisoformat(state['updatedAt']))
            for finding in findings:
                self.assertEqual({'vulnerability', 'locations'}, set(finding))
                self.assertEqual(by_id[finding['vulnerability']['id']], finding['vulnerability'])
                self.assertTrue(1 <= len(finding['locations']) <= 3)
                for location in finding['locations']:
                    self.assertRegex(location['file'], r'^[a-z]{8,20}\.(cs|js|ts|py|java|go|rs|php|sql|yaml|json|html)$')
                    self.assertTrue(1 <= len(location['lineRanges']) <= 3)
                    previous = 0
                    for lines in location['lineRanges']:
                        self.assertEqual({'start', 'end'}, set(lines))
                        self.assertIs(type(lines['start']), int)
                        self.assertIs(type(lines['end']), int)
                        self.assertGreater(lines['start'], previous)
                        self.assertGreaterEqual(lines['end'], lines['start'])
                        previous = lines['end']
            self.assertEqual(state, self.expect('GET', '/api/scans/' + scan['id'], 200)[1])

    def test_new_catalog_entries_are_visible(self):
        self.assertEqual([], self.api.wait(self.start_scan()['id'])['result']['findings'])
        vulnerability = self.create()
        findings = self.api.wait(self.start_scan()['id'])['result']['findings']
        self.assertEqual([vulnerability], [f['vulnerability'] for f in findings])

    def test_restart_loses_in_memory_data(self):
        vulnerability = self.create()
        scan = self.start_scan()
        self.api.wait(scan['id'])
        self.api.stop()
        self.api.start()
        self.expect('GET', '/api/vulnerabilities/' + vulnerability['id'], 404)
        self.expect('GET', '/api/scans/' + scan['id'], 404)
        self.assertEqual([], self.api.wait(self.start_scan()['id'])['result']['findings'])

    def test_completion_cancellation_races_preserve_terminal_state(self):
        for delay in (0, .10, .15, .20):
            scan = self.start_scan()
            time.sleep(delay)
            answers = parallel(lambda _: self.cancel(scan['id']), 12)
            self.assertLessEqual(sum(a['success'] for a in answers), 1)
            state = self.api.wait(scan['id'], ('Cancelled', 'Completed'))
            self.assertEqual('Cancelled' if any(a['success'] for a in answers) else 'Completed', state['status'])
            time.sleep(.2)
            self.assertEqual(state, self.expect('GET', '/api/scans/' + scan['id'], 200)[1])


class QueueTests(HttpTests):
    # Долгая задача удерживает работника; тесты освобождают его HTTP-отменой.
    duration, workers, capacity = 60000, 2, 3

    def occupy_workers(self):
        scans = [self.start_scan() for _ in range(self.workers)]
        for scan in scans:
            state = self.api.wait(scan['id'], ('Running',))
            self.assertIsNone(state['result'])
            self.assertIsNone(state['error'])
        return scans

    def test_invalid_requests_do_not_consume_queue_capacity(self):
        self.occupy_workers()
        for _ in range(self.capacity * 3):
            self.expect('POST', '/api/scans', 400, dict(repositoryUrl='invalid'))
        for _ in range(self.capacity):
            self.start_scan()
        self.expect('POST', '/api/scans', 503, dict(repositoryUrl=URL))

    def test_repeated_running_cancellations_release_workers(self):
        for _ in range(5):
            scans = self.occupy_workers()
            for scan in scans:
                answer = self.cancel(scan['id'])
                self.assertEqual({'id', 'success', 'requestedAt', 'updatedAt', 'status'}, set(answer))
                self.assertTrue(answer['success'])
                self.assertEqual(scan['id'], answer['id'])
                self.assertLessEqual(dt.datetime.fromisoformat(answer['updatedAt']),
                                     dt.datetime.fromisoformat(answer['requestedAt']))
                self.assertEqual('Cancelled', self.api.wait(scan['id'], ('Cancelled',))['status'])

    def test_queued_concurrent_cancellation_never_reaches_running(self):
        running = self.occupy_workers()
        queued = self.start_scan()
        self.assertEqual('Queued', self.expect('GET', '/api/scans/' + queued['id'], 200)[1]['status'])
        answers = parallel(lambda _: self.cancel(queued['id']), 32)
        self.assertEqual(1, sum(a['success'] for a in answers))
        self.assertEqual(1, len({a['updatedAt'] for a in answers}))
        snapshot = self.api.wait(queued['id'], ('Cancelled',))
        for scan in running:
            self.cancel(scan['id'])
        # Следующая задача доказывает, что работник прошёл отменённый элемент очереди.
        next_scan = self.start_scan()
        self.api.wait(next_scan['id'], ('Running',))
        self.assertEqual(snapshot, self.expect('GET', '/api/scans/' + queued['id'], 200)[1])

    def test_parallel_starts_capacity_recovery_and_queued_cancellation(self):
        running = self.occupy_workers()
        results = parallel(lambda _: self.api.request('POST', '/api/scans', dict(repositoryUrl=URL)))
        admitted = [value for code, _, value in results if code == 202]
        self.assertEqual(self.capacity, len(admitted))
        self.assertEqual(self.capacity, len({s['id'] for s in admitted}))
        for code, headers, value in results:
            if code != 202:
                self.assertEqual(503, code, value)
                self.assertEqual('5', headers['Retry-After'])
                self.assertEqual(503, value['status'])
                self.assertTrue(value['traceId'])
        queued = admitted[0]
        self.assertEqual('Queued', self.expect('GET', '/api/scans/' + queued['id'], 200)[1]['status'])
        self.assertTrue(self.cancel(queued['id'])['success'])
        self.assertFalse(self.cancel(queued['id'])['success'])
        # Отмена не извлекает элемент: ёмкость вернётся при чтении работником.
        self.expect('POST', '/api/scans', 503, dict(repositoryUrl=URL))
        for scan in running:
            self.assertTrue(self.cancel(scan['id'])['success'])
        for scan in admitted[1:]:
            self.api.wait(scan['id'], ('Running',))
        self.start_scan()
        state = self.api.wait(queued['id'], ('Cancelled',))
        self.assertIsNone(state['result'])
        self.assertIsNone(state['error'])

    def test_concurrent_cancel_exactly_one_winner_and_unrelated_reads(self):
        running = self.occupy_workers()
        vulnerability = self.create()
        answers = parallel(lambda _: self.cancel(running[0]['id']), 32)
        self.assertEqual(1, sum(a['success'] for a in answers))
        self.assertEqual({'Cancelled'}, {a['status'] for a in answers})
        self.assertEqual(1, len({a['updatedAt'] for a in answers}))
        states = parallel(lambda _: self.expect('GET', '/api/scans/' + running[0]['id'], 200)[1])
        self.assertTrue(all(s == states[0] for s in states))
        self.assertEqual('Running', self.expect('GET', '/api/scans/' + running[1]['id'], 200)[1]['status'])
        self.assertEqual(vulnerability, self.expect('GET', '/api/vulnerabilities/' + vulnerability['id'], 200)[1])
        replacement = self.start_scan()
        self.api.wait(replacement['id'], ('Running',))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument('--docker-image', help='Run each test in a new container from this image')
    options, unittest_args = parser.parse_known_args()
    DOCKER_IMAGE = options.docker_image
    LOGS = LOGS / ('docker' if DOCKER_IMAGE else 'local')
    if not DOCKER_IMAGE and not DLL.is_file():
        raise SystemExit('Build Release first or use run-e2e.ps1')
    unittest.main(argv=[__file__, *unittest_args], verbosity=2)
