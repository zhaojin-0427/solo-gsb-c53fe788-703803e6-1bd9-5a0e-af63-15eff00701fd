"""发布门禁静态分析测试（纯标准库，不执行脱敏、不接触业务数据）。"""
import unittest

from app.contracts import compile_contract
from app.compliance import analyze_publish


def rule(id, path, action):
    return {"id": id, "path": path, "action": action}


def kinds(schema_doc, rules):
    s = compile_contract(schema_doc)
    return {v.kind: v for v in analyze_publish(s, rules)}


class GateBasicTest(unittest.TestCase):
    SCHEMA = {
        "type": "object",
        "properties": {
            "user": {
                "type": "object",
                "properties": {
                    "tax_id": {
                        "type": "string",
                        "x-redaction": {"actions": ["delete", "tokenize"]},
                    }
                },
            }
        },
    }

    def test_uncovered_when_no_rule(self):
        vs = kinds(self.SCHEMA, [])
        self.assertIn("uncovered", vs)
        v = vs["uncovered"]
        self.assertEqual(v.path, "$.user.tax_id")
        self.assertEqual(v.allowed_actions, ["delete", "tokenize"])
        self.assertEqual(v.rules, [])

    def test_witness_is_minimal_and_valid(self):
        s = compile_contract(self.SCHEMA)
        v = analyze_publish(s, [])[0]
        self.assertEqual(
            v.witness, {"user": {"tax_id": "x"}}
        )
        from app.contracts import instance_valid

        self.assertTrue(instance_valid(s.root, v.witness))

    def test_mismatch_action_not_allowed(self):
        vs = kinds(self.SCHEMA, [rule("m", "$.user.tax_id", "mask")])
        self.assertIn("mismatch", vs)
        v = vs["mismatch"]
        self.assertEqual(v.path, "$.user.tax_id")
        self.assertEqual(v.rules[0]["id"], "m")
        self.assertEqual(v.rules[0]["role"], "first_hit")

    def test_allowed_action_passes(self):
        for action in ("delete", "tokenize"):
            self.assertEqual(kinds(self.SCHEMA, [rule("r", "$.user.tax_id", action)]), {})

    def test_shadowed_by_preceding_disallowed_rule(self):
        vs = kinds(
            self.SCHEMA,
            [
                rule("bad", "$.user.tax_id", "mask"),
                rule("ok", "$.user.tax_id", "tokenize"),
            ],
        )
        self.assertIn("shadowed", vs)
        v = vs["shadowed"]
        roles = {r["role"]: r["id"] for r in v.rules}
        self.assertEqual(roles["preceding"], "bad")
        self.assertEqual(roles["shadowed"], "ok")

    def test_allowed_preceding_rule_is_not_shadow(self):
        # delete 本身允许 => 首条即覆盖，后序 tokenize 只是 duplicate
        self.assertEqual(
            kinds(
                self.SCHEMA,
                [
                    rule("d", "$.user.tax_id", "delete"),
                    rule("t", "$.user.tax_id", "tokenize"),
                ],
            ),
            {},
        )

    def test_ancestor_delete_covers_descendants(self):
        self.assertEqual(
            kinds(self.SCHEMA, [rule("d", "$.user", "delete")]), {}
        )
        self.assertEqual(
            kinds(self.SCHEMA, [rule("d", "$", "delete")]), {}
        )

    def test_ancestor_delete_only_counts_first_hit(self):
        # $.user 的首条是 mask（不允许作为 tax_id 的祖先删除），
        # 后序 delete 是 duplicate，tax_id 仍未覆盖
        vs = kinds(
            self.SCHEMA,
            [
                rule("m", "$.user", "mask"),
                rule("d", "$.user", "delete"),
            ],
        )
        self.assertIn("uncovered", vs)


class ArraySemanticsTest(unittest.TestCase):
    SCHEMA = {
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": {
                    "type": "string",
                    "x-redaction": {"actions": ["mask"]},
                },
            }
        },
    }

    def test_wildcard_covers_all_elements(self):
        self.assertEqual(
            kinds(self.SCHEMA, [rule("w", "$.items[*]", "mask")]), {}
        )

    def test_fixed_index_leaves_later_index_uncovered(self):
        vs = kinds(self.SCHEMA, [rule("r0", "$.items[0]", "mask")])
        v = vs.get("uncovered")
        self.assertIsNotNone(v)
        self.assertEqual(v.path, "$.items[1]")
        self.assertEqual(v.witness, {"items": ["x", "x"]})

    def test_wildcard_wrong_action_mismatch(self):
        vs = kinds(self.SCHEMA, [rule("d", "$.items[*]", "delete")])
        self.assertIn("mismatch", vs)
        self.assertEqual(vs["mismatch"].path, "$.items[0]")

    def test_wildcard_shadows_later_specific_rule(self):
        vs = kinds(
            self.SCHEMA,
            [
                rule("d", "$.items[*]", "delete"),
                rule("m", "$.items[0]", "mask"),
            ],
        )
        self.assertIn("shadowed", vs)


class BranchTest(unittest.TestCase):
    def test_oneOf_each_branch_must_be_satisfiably_covered(self):
        schema = {
            "oneOf": [
                {"type": "object", "properties": {
                    "a": {"type": "string"}}},
                {"type": "object", "properties": {
                    "secret": {"type": "string",
                               "x-redaction": {"actions": ["delete"]}}}},
            ]
        }
        vs = kinds(schema, [])
        v = vs["uncovered"]
        self.assertEqual(v.path, "$.secret")
        self.assertEqual(v.branch[0]["combinator"], "oneOf")
        self.assertEqual(v.branch[0]["index"], 1)
        # witness 必须恰好满足分支 1
        from app.contracts import instance_valid

        s = compile_contract(schema)
        self.assertTrue(instance_valid(s.root, v.witness))
        self.assertIn("a", v.witness)  # 判别字段使分支 0 失效

        self.assertEqual(
            kinds(schema, [rule("d", "$.secret", "delete")]), {}
        )

    def test_anyOf_all_branches_checked(self):
        schema = {
            "anyOf": [
                {"type": "object", "properties": {
                    "x": {"type": "string",
                          "x-redaction": {"actions": ["tokenize"]}}}},
                {"type": "object", "properties": {
                    "y": {"type": "string",
                          "x-redaction": {"actions": ["delete"]}}}},
            ]
        }
        vs = kinds(schema, [rule("x", "$.x", "tokenize")])
        self.assertIn("uncovered", vs)
        self.assertEqual(vs["uncovered"].path, "$.y")
        self.assertEqual(
            kinds(
                schema,
                [
                    rule("x", "$.x", "tokenize"),
                    rule("y", "$.y", "delete"),
                ],
            ),
            {},
        )

    def test_allOf_merge_covers_all(self):
        schema = {
            "allOf": [
                {"type": "object", "properties": {
                    "a": {"type": "string",
                          "x-redaction": {"actions": ["mask"]}}}},
                {"type": "object", "properties": {
                    "b": {"type": "string",
                          "x-redaction": {"actions": ["delete"]}}}},
            ]
        }
        vs = kinds(schema, [rule("a", "$.a", "mask")])
        self.assertEqual(vs["uncovered"].path, "$.b")
        self.assertEqual(
            kinds(
                schema,
                [rule("a", "$.a", "mask"), rule("b", "$.b", "delete")],
            ),
            {},
        )

    def test_many_branches_all_enumerated(self):
        # 20 个无 required 区分的 oneOf 分支：每个分支的敏感实例都要暴露
        branch_docs = [
            {"type": "object", "properties": {
                f"k{i}": {"type": "string",
                          "x-redaction": {"actions": ["mask"]}}}}
            for i in range(20)
        ]
        s = compile_contract({"type": "object", "properties": {
            "p": {"type": "object", "oneOf": branch_docs}}})
        compiled_branches = s.root.properties["p"].one_of
        vs = analyze_publish(s, [], max_violations=100)
        paths = {v.path for v in vs}
        self.assertEqual(len(paths), 20)
        self.assertIn("$.p.k0", paths)
        self.assertIn("$.p.k19", paths)
        # 每条 witness 都符合其目标选中分支
        from app.contracts import instance_valid

        for v in vs:
            crumb = v.branch[0]
            self.assertEqual(crumb["combinator"], "oneOf")
            chosen = compiled_branches[crumb["index"]]
            self.assertTrue(instance_valid(chosen, v.witness["p"]))

    def test_action_intersection_empty_always_fails(self):
        schema = {
            "allOf": [
                {"x-redaction": {"actions": ["mask"]}},
                {"x-redaction": {"actions": ["tokenize"]}},
            ],
            "type": "string",
        }
        vs = kinds(schema, [rule("m", "$", "mask")])
        self.assertIn("mismatch", vs)
        self.assertEqual(vs["mismatch"].allowed_actions, [])


class CyclicRefTest(unittest.TestCase):
    SCHEMA = {
        "$defs": {
            "node": {
                "type": "object",
                "properties": {
                    "name": {"type": "string",
                             "x-redaction": {"actions": ["mask"]}},
                    "children": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/node"},
                    },
                },
            }
        },
        "$ref": "#/$defs/node",
    }

    def test_analysis_terminates_and_finds_nested_sensitive(self):
        s = compile_contract(self.SCHEMA)
        vs = analyze_publish(s, [rule("m", "$.name", "mask")])
        paths = {v.path for v in vs}
        self.assertIn("$.children[0].name", paths)

    def test_wildcard_rule_covers_recursive_positions(self):
        s = compile_contract(self.SCHEMA)
        rules = [
            rule("root", "$.name", "mask"),
            rule("rec", "$.children[*].name", "mask"),
        ]
        # 规则深度 2，预算内只检查两层；两层都被覆盖 => 无违规
        self.assertEqual(analyze_publish(s, rules), [])


class PrefixItemsTest(unittest.TestCase):
    SCHEMA = {
        "type": "array",
        "prefixItems": [
            {"type": "object", "properties": {
                "secret": {"type": "string",
                           "x-redaction": {"actions": ["mask"]}}}}
        ],
        "items": {"type": "string"},
    }

    def test_prefix_position_covered(self):
        self.assertEqual(
            kinds(self.SCHEMA, [rule("m", "$[0].secret", "mask")]), {}
        )

    def test_prefix_position_mismatch(self):
        vs = kinds(self.SCHEMA, [rule("d", "$[0].secret", "delete")])
        self.assertIn("mismatch", vs)
        self.assertEqual(vs["mismatch"].witness, [{"secret": "x"}])


class AdditionalPropertiesTest(unittest.TestCase):
    SCHEMA = {
        "type": "object",
        "additionalProperties": {
            "type": "object",
            "properties": {
                "ssn": {"type": "string",
                        "x-redaction": {"actions": ["tokenize"]}}
            },
        },
    }

    def test_extra_property_enumerated(self):
        s = compile_contract(self.SCHEMA)
        vs = analyze_publish(s, [])
        v = vs[0]
        self.assertEqual(v.path, "$.extra.ssn")
        from app.contracts import instance_valid

        self.assertTrue(instance_valid(s.root, v.witness))

    def test_fixed_name_rule_does_not_match_fresh_key(self):
        # $.extra.ssn 是具体名；witness 用未声明的新键 extra1
        vs = kinds(self.SCHEMA, [rule("t", "$.extra.ssn", "tokenize")])
        self.assertIn("uncovered", vs)
        self.assertEqual(vs["uncovered"].path, "$.extra1.ssn")


class RootRedactionTest(unittest.TestCase):
    def test_root_delete_ok_other_action_mismatch(self):
        schema = {"type": "object",
                  "x-redaction": {"actions": ["delete"]}}
        self.assertEqual(kinds(schema, [rule("d", "$", "delete")]), {})
        self.assertIn("mismatch", kinds(schema, [rule("m", "$", "mask")]))


if __name__ == "__main__":
    unittest.main()
