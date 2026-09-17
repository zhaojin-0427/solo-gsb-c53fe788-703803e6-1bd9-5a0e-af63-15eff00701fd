import unittest

from app.pathlang import PathSyntaxError, format_path, match, parse_path


class PathLangTest(unittest.TestCase):
    def test_parse_valid(self):
        self.assertEqual(parse_path("$"), ())
        self.assertEqual(parse_path("$.name"), ("name",))
        self.assertEqual(parse_path("$.a.b"), ("a", "b"))
        self.assertEqual(parse_path("$.a[0]"), ("a", 0))
        self.assertEqual(parse_path("$.a[*]"), ("a", "*"))
        self.assertEqual(parse_path("$[*][12].x"), ("*", 12, "x"))

    def test_parse_invalid(self):
        bad = [
            "",
            "name",          # 必须以 $ 开头
            "$..a",          # 无点号
            "$['a']",        # 不允许括号字符串
            "$.*",           # 不允许点号通配
            "$[01]",         # 前导零
            "$[-1]",         # 负索引
            "$[ ]",
            "$a",            # 裸字段必须以点开头
            "$.a-b",         # 非法字符
        ]
        for p in bad:
            with self.subTest(p=p):
                with self.assertRaises(PathSyntaxError):
                    parse_path(p)

    def test_match_object_and_array(self):
        doc = {"a": {"b": [{"x": 1}, {"x": 2}]}}
        hits = match(doc, parse_path("$.a.b[*].x"))
        self.assertEqual([h.node for h in hits], [1, 2])
        self.assertEqual([h.prefix for h in hits], [("a", "b", 0, "x"), ("a", "b", 1, "x")])

    def test_match_root(self):
        doc = {"a": 1}
        hits = match(doc, parse_path("$"))
        self.assertEqual(len(hits), 1)
        self.assertIs(hits[0].node, doc)
        self.assertEqual(hits[0].prefix, ())

    def test_match_missing_and_wildcard_on_non_array(self):
        doc = {"a": {"b": 1}}
        self.assertEqual(match(doc, parse_path("$.x.y")), [])
        self.assertEqual(match(doc, parse_path("$.a[*]")), [])
        self.assertEqual(match(doc, parse_path("$.a[0]")), [])
        self.assertEqual(match({"a": [1]}, parse_path("$.a[5]")), [])

    def test_format_path(self):
        self.assertEqual(format_path(("a", 0, "b")), "$.a[0].b")
        self.assertEqual(format_path(()), "$")


if __name__ == "__main__":
    unittest.main()
