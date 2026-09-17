import os
import unittest

os.environ.setdefault("ALLOW_INSECURE_DEV_KEY", "1")

from app.engine import RuleSpec, apply_document


def r(id, path, action, **kw):
    return RuleSpec(id=id, path=path, action=action, **kw)


class EngineTest(unittest.TestCase):
    def test_mask_keeps_edges(self):
        doc = {"name": "alice"}
        out = apply_document(doc, [r("r1", "$.name", "mask", keep_prefix=1, keep_suffix=1)])
        self.assertEqual(out["document"], {"name": "a***e"})

    def test_mask_non_string_is_placeholder(self):
        out = apply_document({"n": 123}, [r("r1", "$.n", "mask")])
        self.assertEqual(out["document"], {"n": "***"})
        out2 = apply_document({"n": True}, [r("r1", "$.n", "mask")])
        self.assertEqual(out2["document"], {"n": "***"})

    def test_tokenize_deterministic(self):
        out1 = apply_document({"t": 123}, [r("r1", "$.t", "tokenize")])
        out2 = apply_document({"t": 123}, [r("r1", "$.t", "tokenize")])
        out3 = apply_document({"t": 124}, [r("r1", "$.t", "tokenize")])
        self.assertEqual(out1["document"]["t"], out2["document"]["t"])
        self.assertTrue(out1["document"]["t"].startswith("hmac."))
        self.assertNotEqual(out1["document"]["t"], out3["document"]["t"])

    def test_first_rule_wins_per_node(self):
        doc = {"a": "x", "b": "y"}
        out = apply_document(
            doc,
            [
                r("keep", "$.a", "mask"),
                r("dup", "$.a", "delete"),
                r("delb", "$.b", "delete"),
            ],
        )
        self.assertEqual(set(out["document"].keys()), {"a"})
        traces = {t["rule_id"]: t for t in out["trace"]}
        dup_hit = traces["dup"]["hits"][0]
        self.assertEqual(dup_hit["status"], "duplicate")
        self.assertEqual(dup_hit["rule_id"], "keep")
        self.assertEqual(traces["dup"]["applied"], 0)

    def test_array_delete_descending(self):
        doc = {"items": [{"x": 1}, {"x": 2}, {"x": 3}]}
        out = apply_document(
            doc, [r("d", "$.items[*]", "delete")]
        )
        self.assertEqual(out["document"], {"items": []})

    def test_array_delete_specific_indices(self):
        doc = {"items": [0, 1, 2, 3]}
        out = apply_document(
            doc, [r("d", "$.items[2]", "delete"), r("d0", "$.items[0]", "delete")]
        )
        # 降序删除：先删 2 再删 0
        self.assertEqual(out["document"]["items"], [1, 3])

    def test_descendant_skipped_after_ancestor_delete(self):
        doc = {"user": {"name": "a", "address": {"city": "x"}}}
        out = apply_document(
            doc,
            [
                r("du", "$.user.address", "delete"),
                r("mc", "$.user.address.city", "mask"),
                r("mn", "$.user.name", "mask"),
            ],
        )
        self.assertEqual(out["document"], {"user": {"name": "***"}})
        traces = {t["rule_id"]: t for t in out["trace"]}
        self.assertEqual(traces["mc"]["skipped"], 1)
        self.assertEqual(traces["mc"]["hits"][0]["status"], "skipped")
        self.assertEqual(traces["mn"]["applied"], 1)

    def test_root_delete_skips_all_descendants(self):
        doc = {"a": {"b": 1}}
        out = apply_document(doc, [r("rd", "$", "delete"), r("m", "$.a.b", "mask")])
        self.assertIsNone(out["document"])
        traces = {t["rule_id"]: t for t in out["trace"]}
        self.assertEqual(traces["m"]["skipped"], 1)

    def test_wildcard_hits_use_original_document(self):
        # 通配在原始 3 元素数组上展开；但同一节点按声明顺序取首条，
        # 因此 mask 规则先占住节点 2 时，后面的删除规则对该节点重复命中
        doc = {"items": ["a", "b", "c"]}
        out = apply_document(
            doc,
            [
                r("mask_all", "$.items[*]", "mask"),
                r("del_last", "$.items[2]", "delete"),
            ],
        )
        self.assertEqual(out["document"], {"items": ["***", "***", "***"]})
        traces = {t["rule_id"]: t for t in out["trace"]}
        self.assertEqual(traces["mask_all"]["applied"], 3)
        self.assertEqual(traces["del_last"]["applied"], 0)
        self.assertEqual(traces["del_last"]["hits"][0]["status"], "duplicate")

        # 同节点重复声明时按声明顺序取首条 => 节点 2 被删除而非遮盖
        out2 = apply_document(
            {"items": ["a", "b", "c"]},
            [
                r("del_last", "$.items[2]", "delete"),
                r("mask_all", "$.items[*]", "mask"),
            ],
        )
        self.assertEqual(out2["document"], {"items": ["***", "***"]})

    def test_no_hits_rule_has_empty_trace(self):
        out = apply_document({"a": 1}, [r("x", "$.missing", "delete")])
        self.assertEqual(out["trace"][0]["matched"], 0)
        self.assertEqual(out["trace"][0]["applied"], 0)

    def test_trace_has_no_values(self):
        doc = {"secret": "supersecretvalue"}
        out = apply_document(doc, [r("x", "$.secret", "mask")])
        text = repr(out["trace"])
        self.assertNotIn("supersecretvalue", text)

    def test_wildcard_then_field_transforms_all_elements(self):
        doc = {"users": [{"name": "alice"}, {"name": "bob"}]}
        out = apply_document(doc, [r("m", "$.users[*].name", "mask")])
        self.assertEqual(
            out["document"], {"users": [{"name": "***"}, {"name": "***"}]}
        )


if __name__ == "__main__":
    unittest.main()
