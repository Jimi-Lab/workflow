from __future__ import annotations

import unittest

from vulnversion.stage3_verify.version_registry import line_family_key, line_key


class TestRepoAwareVersionTreeLines(unittest.TestCase):
    def test_curl_stays_single_line(self) -> None:
        self.assertEqual(line_key("curl", "curl-7_68_0"), "main")
        self.assertEqual(line_key("curl", "curl-8_4_0"), "main")

    def test_imagemagick_stays_major_minor_line(self) -> None:
        self.assertEqual(line_key("ImageMagick", "7.0.10-0"), "7.0")
        self.assertEqual(line_key("ImageMagick", "7.1.1-10"), "7.1")

    def test_openssl_merges_only_mainline_09(self) -> None:
        self.assertEqual(line_key("openssl", "OpenSSL_0_9_6"), "0.9")
        self.assertEqual(line_key("openssl", "OpenSSL_0_9_8za"), "0.9")
        self.assertEqual(line_key("openssl", "OpenSSL_1_0_0"), "1.0.0")
        self.assertEqual(line_key("openssl", "OpenSSL_1_0_1"), "1.0.1")
        self.assertEqual(line_key("openssl", "OpenSSL_1_0_2u"), "1.0.2")
        self.assertEqual(line_key("openssl", "OpenSSL_1_1_1w"), "1.1.1")
        self.assertEqual(line_key("openssl", "openssl-3.0.0"), "3.0")

    def test_openssl_keeps_fips_and_engine_partitions(self) -> None:
        self.assertEqual(line_key("openssl", "OpenSSL-fips-2_0-pl1"), "fips-2.0")
        self.assertEqual(line_key("openssl", "OpenSSL-engine-0_9_6"), "engine-0.9.6")
        self.assertEqual(line_family_key("openssl", "0.9"), "openssl-mainline")
        self.assertEqual(line_family_key("openssl", "1.0.2"), "openssl-mainline")
        self.assertEqual(line_family_key("openssl", "fips-2.0"), "openssl-fips")
        self.assertEqual(line_family_key("openssl", "engine-0.9.6"), "openssl-engine")


if __name__ == "__main__":
    unittest.main()
