import unittest

from app.jcs import canonicalize


class JCSTest(unittest.TestCase):
    def test_primitives(self):
        self.assertEqual(canonicalize(None), b"null")
        self.assertEqual(canonicalize(True), b"true")
        self.assertEqual(canonicalize(False), b"false")
        self.assertEqual(canonicalize(-42), b"-42")

    def test_integer_float_renders_without_dot_zero(self):
        self.assertEqual(canonicalize(100.0), b"100")
        self.assertEqual(canonicalize(0.0), b"0")
        self.assertEqual(canonicalize(-0.0), b"0")

    def test_shortest_roundtrip_examples(self):
        self.assertEqual(canonicalize(0.25), b"0.25")
        self.assertEqual(canonicalize(1.5), b"1.5")
        self.assertEqual(canonicalize(0.001), b"0.001")
        self.assertEqual(canonicalize(0.000001), b"0.000001")

    def test_exponent_thresholds(self):
        # n == 21 仍用整数形式；n == 22 才转科学计数
        self.assertEqual(canonicalize(1e20), b"100000000000000000000")
        self.assertEqual(canonicalize(1e21), b"1e+21")
        # n == -6 仍用小数形式；n == -7 才转科学计数
        self.assertEqual(canonicalize(0.000001), b"0.000001")
        self.assertEqual(canonicalize(1e-7), b"1e-7")
        self.assertEqual(
            canonicalize(123456789012345680000.0),
            b"123456789012345680000",
        )

    def test_object_keys_sorted_utf16(self):
        # 键顺序不影响规范化结果
        a = canonicalize({"b": 1, "a": 2})
        b = canonicalize({"a": 2, "b": 1})
        self.assertEqual(a, b'{"a":2,"b":1}')
        self.assertEqual(a, b)

    def test_arrays_keep_order(self):
        self.assertEqual(canonicalize([3, 1, 2]), b"[3,1,2]")

    def test_nested_and_string(self):
        self.assertEqual(
            canonicalize({"k": [True, None, "x\"y\n"]}),
            b'{"k":[true,null,"x\\"y\\n"]}',
        )

    def test_non_finite_rejected(self):
        from app.exceptions import ClientError
        from app.jcs import digest

        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ClientError):
                digest(bad)


if __name__ == "__main__":
    unittest.main()
