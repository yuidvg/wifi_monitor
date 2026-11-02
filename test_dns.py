import unittest

from compare_dns import compare
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


class TwoMacComparisonTest(unittest.TestCase):
    @staticmethod
    def sample(epoch, **seconds):
        return {"epoch": epoch, "timings": {key: {"status": "ok", "seconds": s}
                                            for key, s in seconds.items()}}

    def test_both_checks_all_samples_in_window_and_names_each_path(self):
        main = self.sample(100, dns_lookup=2)
        peers = [self.sample(99, dns_lookup=0.01), self.sample(130, gateway_dns=2.4)]
        result = compare(main, peers)
        self.assertEqual((result["scope"], result["peer_slow"], result["offset_s"]),
                         ("both", ["gateway_dns"], 30))
        self.assertEqual(compare(main, [self.sample(131, dns_lookup=2.2)])["scope"], "unconfirmed")

    def test_main_only_requires_success_for_the_affected_paths(self):
        main = self.sample(100, dns_lookup=2.8, https=2.1)
        fast = self.sample(97, dns_lookup=0.1, https=0.3)
        self.assertEqual(compare(main, [fast], peer_latest=130)["scope"], "main_only")
        self.assertEqual(compare(main, [fast], peer_latest=129)["scope"], "unconfirmed")
        for peer in (self.sample(99, dns_lookup=0.01), self.sample(101)):
            self.assertEqual(compare(main, [peer], peer_latest=130)["scope"], "unconfirmed")
        incomplete = self.sample(100)
        incomplete["timings"]["dns_lookup"] = {"status": "error", "seconds": None}
        self.assertEqual(compare(main, [fast, incomplete], peer_latest=130)["scope"], "unconfirmed")


if __name__ == "__main__":
    unittest.main()
