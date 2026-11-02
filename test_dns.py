import unittest

from wifi_monitor import configured_tailscale_dns, dns_timings, slow_dns_paths


class DnsTimingTest(unittest.TestCase):
    def test_system_and_curl_detect_slow_success_independently(self):
        row = {
            "dns_lookup": {"exit_code": 0, "elapsed_s": 2.0, "stdout": "ip_address: 192.0.2.1"},
            "https": {"exit_code": 0, "stdout": "200 dns=2.537313 connect=2.59 total=2.71"},
        }
        self.assertEqual(slow_dns_paths(dns_timings(row)), ["dns_lookup", "https"])
        row["https"]["stdout"] = "200 dns=0.02 connect=2.59 total=2.71"
        row["dns_lookup"]["elapsed_s"] = 1.999
        self.assertEqual(slow_dns_paths(dns_timings(row)), [])

    def test_timeout_requires_dns_phase(self):
        probe = {"exit_code": 28, "stdout": "000 dns=0.000000 connect=0 total=3.1",
                 "stderr": "curl: (28) Resolving timed out after 3068 milliseconds"}
        self.assertEqual(slow_dns_paths(dns_timings({"https": probe})), ["https"])
        probe["stderr"] = "curl: (28) Connection timed out after 3068 milliseconds"
        self.assertEqual(dns_timings({"https": probe}), {})

    def test_pair_uses_wire_latency_and_keeps_missing_or_timed_out_peer_distinct(self):
        answer = "status: NOERROR\nwww.apple.com. 20 IN A 192.0.2.1\n;; Query time: {} msec"
        row = {key: {"exit_code": 0, "elapsed_s": 3.5, "stdout": answer.format(ms)}
               for key, ms in (("tailscale_dns", 2000), ("gateway_dns", 8))}
        self.assertEqual(slow_dns_paths(dns_timings(row)), ["tailscale_dns"])
        row.pop("tailscale_dns")
        row["gateway_dns"] = {"exit_code": 9, "stdout": "connection timed out", "elapsed_s": 5.1}
        self.assertEqual(dns_timings(row), {"gateway_dns": {"status": "timeout", "seconds": 5.1}})
        self.assertEqual(slow_dns_paths(dns_timings(row)), [])

    def test_resolver_detection(self):
        self.assertIsNone(configured_tailscale_dns({"stdout": "nameserver[0] : 192.0.2.1"}))
        self.assertEqual(configured_tailscale_dns({"stdout": "  nameserver[1] : fd7a:115c:a1e0::53"}),
                         "fd7a:115c:a1e0::53")


if __name__ == "__main__":
    unittest.main()
