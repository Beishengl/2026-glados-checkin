import json
import os
import unittest
from unittest import mock

import checkin


class FakeClient:
    def __init__(self, results):
        self.results = iter(results)
        self.calls = 0

    def checkin(self):
        self.calls += 1
        return next(self.results)


class CheckinResultTests(unittest.TestCase):
    def test_current_observation_message_is_normal(self):
        result = {
            'code': 1,
            'message': "Today's observation logged. Return tomorrow for more points.",
        }
        self.assertTrue(checkin.is_normal_checkin_result(result))

    def test_historic_success_message_is_normal(self):
        self.assertTrue(
            checkin.is_normal_checkin_result({'code': 0, 'message': 'Checkin! Got 15 Points'})
        )

    def test_unknown_error_is_failure(self):
        self.assertFalse(checkin.is_normal_checkin_result({'code': 2, 'message': 'Cookie expired'}))

    def test_permission_failure_is_not_retryable(self):
        self.assertTrue(
            checkin.is_non_retryable_checkin_result({'code': -2, 'message': '没有权限'})
        )

    def test_http_rejection_is_not_retryable(self):
        self.assertTrue(
            checkin.is_non_retryable_checkin_result({'http_status': 401, 'reason': 'http-auth-rejected'})
        )
        self.assertTrue(
            checkin.is_non_retryable_checkin_result({'http_status': 403, 'reason': 'http-auth-rejected'})
        )

    def test_device_mismatch_is_not_retryable(self):
        self.assertTrue(
            checkin.is_non_retryable_checkin_result(
                {'code': 4, 'reason': 'device-mismatch', 'message': 'denied'}
            )
        )

    @mock.patch('checkin.time.sleep')
    def test_retry_stops_after_success(self, sleep):
        client = FakeClient([
            None,
            {'code': 0, 'message': 'Checkin! Got 15 Points'},
        ])

        result, success = checkin.checkin_with_retry(client, attempts=3, delay_seconds=1)

        self.assertTrue(success)
        self.assertEqual(result['code'], 0)
        self.assertEqual(client.calls, 2)
        sleep.assert_called_once_with(1)

    @mock.patch('checkin.time.sleep')
    def test_retry_stops_immediately_for_auth_failure(self, sleep):
        client = FakeClient([
            {'code': -2, 'message': '没有权限'},
            {'code': 0, 'message': 'Checkin! Got 15 Points'},
        ])

        result, success = checkin.checkin_with_retry(client, attempts=3, delay_seconds=1)

        self.assertFalse(success)
        self.assertEqual(result['code'], -2)
        self.assertEqual(client.calls, 1)
        sleep.assert_not_called()

    @mock.patch('checkin.time.sleep')
    def test_automated_detection_without_reason_does_not_retry(self, sleep):
        failure = {
            'code': 4,
            'message': 'Automated check-in detected. Please sign in again to continue.',
        }
        client = FakeClient([failure])

        result, success = checkin.checkin_with_retry(client, attempts=3)

        self.assertFalse(success)
        self.assertEqual(result, failure)
        self.assertEqual(client.calls, 1)
        sleep.assert_not_called()


class BrowserHeaderTests(unittest.TestCase):
    def test_custom_chrome_user_agent_builds_matching_client_hints(self):
        user_agent = (
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/154.0.0.0 Safari/537.36'
        )
        with mock.patch.dict(os.environ, {'GLADOS_USER_AGENT': user_agent}):
            headers = checkin.get_browser_headers()

        self.assertEqual(headers['User-Agent'], user_agent)
        self.assertIn('"Chromium";v="154"', headers['Sec-CH-UA'])
        self.assertIn('"Google Chrome";v="154"', headers['Sec-CH-UA'])
        self.assertEqual(headers['Sec-CH-UA-Mobile'], '?0')
        self.assertEqual(headers['Sec-CH-UA-Platform'], '"macOS"')

    def test_empty_user_agent_uses_compatible_default(self):
        with mock.patch.dict(os.environ, {'GLADOS_USER_AGENT': ''}):
            headers = checkin.get_browser_headers()

        self.assertIn('Chrome/120.0.0.0', headers['User-Agent'])
        self.assertIn('"Chromium";v="120"', headers['Sec-CH-UA'])
        self.assertEqual(headers['Sec-CH-UA-Platform'], '"Windows"')


class CookieTests(unittest.TestCase):
    def test_cookie_header_prefix_is_removed(self):
        raw = 'Cookie: gld:sess=abc; gld:sess.sig=def'
        self.assertEqual(checkin.extract_cookie(raw), 'gld:sess=abc; gld:sess.sig=def')

    def test_cookie_editor_json_export_preserves_current_session(self):
        raw = json.dumps([
            {'name': 'gld:sess', 'value': 'abc'},
            {'name': 'gld:sess.sig', 'value': 'def'},
            {'name': 'other', 'value': '123'},
        ])
        cookie = checkin.extract_cookie(raw)

        self.assertEqual(checkin.get_session_cookie_kind(cookie), 'gld')
        self.assertIn('gld:sess=abc', cookie)
        self.assertIn('gld:sess.sig=def', cookie)

    def test_json_token_uses_real_cookie_name(self):
        raw = json.dumps({'token': 'legacy-jwt-token'})
        self.assertEqual(checkin.extract_cookie(raw), 'koa:sess=legacy-jwt-token')

    def test_current_signed_session_is_detected(self):
        cookie = 'foo=1; gld:sess=abc; bar=2; gld:sess.sig=def'
        self.assertEqual(checkin.get_session_cookie_kind(cookie), 'gld')

    def test_legacy_signed_session_is_detected(self):
        cookie = 'koa:sess=abc; koa:sess.sig=def'
        self.assertEqual(checkin.get_session_cookie_kind(cookie), 'koa')

    def test_incomplete_current_session_is_not_accepted(self):
        cookie = 'gld:sess=abc; other=def'
        self.assertIsNone(checkin.get_session_cookie_kind(cookie))

    def test_missing_configuration_returns_no_accounts(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(checkin.get_cookies(), [])

    def test_get_cookies_preserves_multiple_cookie_headers(self):
        account1 = 'gld:sess=one; gld:sess.sig=one-sig'
        account2 = 'gld:sess=two; gld:sess.sig=two-sig'
        with mock.patch.dict(os.environ, {'GLADOS_COOKIE': f'{account1}\n{account2}'}):
            self.assertEqual(checkin.get_cookies(), [account1, account2])

    def test_get_cookies_preserves_formatted_json_as_one_account(self):
        formatted_json = (
            '[\n'
            '  {"name": "gld:sess", "value": "one"},\n'
            '  {"name": "gld:sess.sig", "value": "one-sig"}\n'
            ']'
        )
        with mock.patch.dict(os.environ, {'GLADOS_COOKIE': formatted_json}):
            cookies = checkin.get_cookies()

        self.assertEqual(len(cookies), 1)
        self.assertEqual(checkin.get_session_cookie_kind(cookies[0]), 'gld')

    def test_get_cookies_preserves_ampersands_in_json_values(self):
        raw_json = json.dumps([
            {'name': 'gld:sess', 'value': 'one&two'},
            {'name': 'gld:sess.sig', 'value': 'sig'},
        ])
        with mock.patch.dict(os.environ, {'GLADOS_COOKIE': raw_json}):
            cookies = checkin.get_cookies()

        self.assertEqual(len(cookies), 1)
        self.assertIn('gld:sess=one&two', cookies[0])

    def test_get_cookies_parses_formatted_legacy_token_json(self):
        formatted_json = '{\n  "token": "one"\n}'
        with mock.patch.dict(os.environ, {'GLADOS_COOKIE': formatted_json}):
            self.assertEqual(checkin.get_cookies(), ['koa:sess=one'])

    def test_get_cookies_rejects_malformed_json(self):
        with mock.patch.dict(os.environ, {'GLADOS_COOKIE': '[{"name": "broken"'}):
            self.assertEqual(checkin.get_cookies(), [])

    @mock.patch('checkin.requests.get')
    def test_full_cookie_header_is_forwarded_to_api(self, request_get):
        request_get.return_value.status_code = 200
        request_get.return_value.json.return_value = {'code': 0, 'data': {}}

        cookie = 'gld:sess=abc; gld:sess.sig=def; extra=123'
        checkin.GLaDOS(cookie).req('GET', '/api/user/status')

        sent_cookie = request_get.call_args.kwargs['headers']['Cookie']
        self.assertEqual(sent_cookie, cookie)


class ExchangePlanTests(unittest.TestCase):
    def test_defaults_to_plan500(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(checkin.get_exchange_plan(), 'plan500')

    def test_off_disables_exchange(self):
        for val in ('off', 'OFF', 'false', '0', 'disabled', ''):
            with mock.patch.dict(os.environ, {'EXCHANGE_PLAN': val}):
                self.assertIsNone(checkin.get_exchange_plan())

    def test_invalid_value_disables_exchange(self):
        with mock.patch.dict(os.environ, {'EXCHANGE_PLAN': 'plan999'}):
            self.assertIsNone(checkin.get_exchange_plan())


class FakeGLaDOS:
    def __init__(self, points, exchange_response):
        self.points = points
        self.exchange_response = exchange_response
        self.refresh_calls = 0

    def exchange(self, plan):
        self.plan_sent = plan
        return self.exchange_response

    def get_status(self):
        self.refresh_calls += 1

    def get_points(self):
        self.refresh_calls += 1


class AutoExchangeTests(unittest.TestCase):
    def test_skips_when_points_below_threshold(self):
        client = FakeGLaDOS('499', {'code': 0, 'message': 'ok'})

        result = checkin.auto_exchange(client, 'plan500')

        self.assertIn('积分不足', result)
        self.assertIn('499/500', result)
        self.assertFalse(hasattr(client, 'plan_sent'))

    def test_exchanges_and_refreshes_when_points_reach_threshold(self):
        client = FakeGLaDOS('500', {'code': 0, 'message': 'ok'})

        result = checkin.auto_exchange(client, 'plan500')

        self.assertIn('兑换成功 +100天', result)
        self.assertEqual(client.plan_sent, 'plan500')
        self.assertEqual(client.refresh_calls, 2)

    def test_reports_failure_without_refresh(self):
        client = FakeGLaDOS('500', {'code': 1, 'message': 'denied'})

        result = checkin.auto_exchange(client, 'plan500')

        self.assertIn('兑换失败', result)
        self.assertIn('denied', result)
        self.assertEqual(client.refresh_calls, 0)

    def test_unreadable_points_is_reported(self):
        client = FakeGLaDOS('?', {'code': 0, 'message': 'ok'})

        result = checkin.auto_exchange(client, 'plan500')

        self.assertIn('积分查询失败', result)
        self.assertFalse(hasattr(client, 'plan_sent'))


class DiagnosticTests(unittest.TestCase):
    @mock.patch('checkin.log')
    @mock.patch('checkin.requests.get')
    def test_request_error_does_not_expose_cookie(self, request_get, log):
        cookie = 'gld:sess=private-cookie; gld:sess.sig=private-signature'
        request_get.side_effect = checkin.requests.exceptions.InvalidHeader(cookie)

        result = checkin.GLaDOS(cookie).req('GET', '/api/user/status')
        self.assertTrue(result['request_failed'])
        self.assertTrue(result['invalid_headers'])
        self.assertNotIn('private-cookie', str(result))

        printed = str(log.call_args_list)
        self.assertNotIn('private-cookie', printed)
        self.assertNotIn('private-signature', printed)

    @mock.patch('checkin.log')
    @mock.patch('checkin.telegram_push')
    @mock.patch('checkin.pushplus')
    @mock.patch('checkin.GLaDOS')
    def test_diagnostic_queries_status_without_writes_or_private_logs(
        self, client_class, pushplus, telegram, log,
    ):
        cookie = 'gld:sess=private-cookie; gld:sess.sig=private-signature'
        client = client_class.return_value
        client.req.return_value = {
            'code': 0,
            'data': {'email': 'user@example.com', 'leftDays': '10'},
        }

        exit_code = checkin.diagnose_accounts([cookie])

        self.assertEqual(exit_code, 0)
        client.req.assert_called_once_with('GET', '/api/user/status')
        pushplus.assert_not_called()
        telegram.assert_not_called()
        printed = str(log.call_args_list)
        self.assertNotIn('user@example.com', printed)
        self.assertNotIn('private-cookie', printed)
        self.assertNotIn('private-signature', printed)

    @mock.patch('checkin.GLaDOS')
    def test_diagnostic_reports_failure_if_any_account_fails(self, client_class):
        client = client_class.return_value
        client.req.side_effect = [
            {'code': 0, 'data': {'email': 'one@example.com', 'leftDays': '10'}},
            {'code': -2, 'message': '没有权限'},
        ]

        exit_code = checkin.diagnose_accounts(['cookie1', 'cookie2'])

        self.assertEqual(exit_code, 1)

    @mock.patch('checkin.GLaDOS')
    def test_diagnostic_auth_and_malformed_responses_fail(self, client_class):
        client = client_class.return_value
        client.req.side_effect = [
            None,
            {},
            {'code': -2, 'message': '没有权限'},
            {'code': 0, 'data': {}},
            {'code': 0, 'data': 'not-a-dict'},
            {'code': 1, 'message': 'wrong code'},
        ]

        for _ in range(6):
            self.assertEqual(checkin.diagnose_accounts(['cookie']), 1)


if __name__ == '__main__':
    unittest.main()
