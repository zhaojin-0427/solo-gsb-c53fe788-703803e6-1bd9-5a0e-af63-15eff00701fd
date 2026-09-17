import unittest

from app.gate import analyze_contract


def r(id, path, action):
    return {"id": id, "path": path, "action": action}


def kinds(violations):
    return sorted(v["kind"] for v in violations)


class GateBasicTest(unittest.TestCase):
    SCHEMA = {
        "type": "object",
        "properties": {
            "user": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "x-redaction": {"actions": ["mask"]},
                    },
                    "tax_id": {
                        "type": ["string", "number"],
                        "x-redaction": {"actions": ["tokenize"]},
                    },
                },
                "required": ["name"],
            }
        },
    }

    def test_no_sensitive_nodes_passes(self):
        self.assertEqual(analyze_contract({"type": "object"}, []), [])
        self.assertEqual(analyze_contract(True, []), [])
        self.assertEqual(analyze_contract(False, []), [])

    def test_covered(self):
        violations = analyze_contract(
            self.SCHEMA,
            [r("r1", "$.user.name", "mask"), r("r2", "$.user.tax_id", "tokenize")],
        )
        self.assertEqual(violations, [])

    def test_uncovered_reports_shortest_path_and_witness(self):
        violations = analyze_contract(self.SCHEMA, [r("r2", "$.user.tax_id", "tokenize")])
        self.assertEqual(kinds(violations), ["uncovered"])
        v = violations[0]
        self.assertEqual(v["path"], "$.user.name")
        self.assertEqual(v["allowed_actions"], ["mask"])
        self.assertIsNone(v["effective_action"])
        self.assertEqual(v["rules"], [])
        self.assertEqual(v["schema_path"], "#/properties/user/properties/name")
        # 最小 witness：只含敏感路径与 required 兄弟
        self.assertEqual(v["witness"], {"user": {"name": ""}})

    def test_action_mismatch(self):
        violations = analyze_contract(
            self.SCHEMA,
            [r("r1", "$.user.name", "delete"), r("r2", "$.user.tax_id", "tokenize")],
        )
        self.assertEqual(kinds(violations), ["action_mismatch"])
        v = violations[0]
        self.assertEqual(v["path"], "$.user.name")
        self.assertEqual(v["effective_action"], "delete")
        self.assertEqual([x["id"] for x in v["rules"]], ["r1"])

    def test_shadowed_by_prior_rule(self):
        violations = analyze_contract(
            self.SCHEMA,
            [
                r("r1", "$.user.name", "delete"),
                r("r2", "$.user.name", "mask"),
                r("r3", "$.user.tax_id", "tokenize"),
            ],
        )
        self.assertEqual(kinds(violations), ["shadowed"])
        v = violations[0]
        self.assertEqual(v["effective_action"], "delete")
        self.assertEqual([x["id"] for x in v["rules"]], ["r1", "r2"])

    def test_first_allowed_hit_wins(self):
        violations = analyze_contract(
            self.SCHEMA,
            [
                r("r1", "$.user.name", "mask"),
                r("r2", "$.user.name", "delete"),
                r("r3", "$.user.tax_id", "tokenize"),
            ],
        )
        self.assertEqual(violations, [])

    def test_root_sensitive(self):
        schema = {"x-redaction": {"actions": ["tokenize"]}}
        self.assertEqual(analyze_contract(schema, [r("r", "$", "tokenize")]), [])
        violations = analyze_contract(schema, [])
        self.assertEqual(kinds(violations), ["uncovered"])
        self.assertEqual(violations[0]["path"], "$")


class GateAncestorTest(unittest.TestCase):
    SCHEMA = {
        "type": "object",
        "properties": {
            "user": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "x-redaction": {"actions": ["mask", "delete"]},
                    }
                },
            }
        },
    }

    def test_ancestor_delete_covers_when_allowed(self):
        self.assertEqual(
            analyze_contract(self.SCHEMA, [r("r", "$.user", "delete")]), []
        )

    def test_ancestor_action_must_be_allowed(self):
        schema = {
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "x-redaction": {"actions": ["mask"]},
                        }
                    },
                }
            },
        }
        violations = analyze_contract(schema, [r("r", "$.user", "delete")])
        self.assertEqual(kinds(violations), ["action_mismatch"])
        self.assertEqual(violations[0]["effective_action"], "delete")

    def test_shallowest_ancestor_decides_regardless_of_order(self):
        # 深层规则声明在前、浅层删除声明在后：引擎中浅层删除仍然生效
        violations = analyze_contract(
            self.SCHEMA,
            [r("deep", "$.user.name", "mask"), r("shallow", "$.user", "delete")],
        )
        self.assertEqual(violations, [])

    def test_deeper_rule_does_not_cover_node_itself(self):
        schema = {
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                    "x-redaction": {"actions": ["mask"]},
                }
            },
        }
        violations = analyze_contract(schema, [r("r", "$.user.name", "mask")])
        self.assertEqual(kinds(violations), ["uncovered"])
        self.assertEqual(violations[0]["path"], "$.user")


class GateArrayTest(unittest.TestCase):
    SCHEMA = {
        "type": "object",
        "properties": {
            "users": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "x-redaction": {"actions": ["mask"]},
                        }
                    },
                },
            }
        },
    }

    def test_wildcard_rule_covers_all_indices(self):
        self.assertEqual(
            analyze_contract(self.SCHEMA, [r("r", "$.users[*].name", "mask")]), []
        )

    def test_concrete_index_leaves_others_uncovered(self):
        violations = analyze_contract(
            self.SCHEMA, [r("r", "$.users[0].name", "mask")]
        )
        self.assertEqual(kinds(violations), ["uncovered"])
        v = violations[0]
        self.assertEqual(v["path"], "$.users[1].name")
        self.assertEqual(v["witness"], {"users": [{}, {"name": ""}]})

    def test_ancestor_wildcard_delete(self):
        schema = {
            "type": "object",
            "properties": {
                "users": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "x-redaction": {"actions": ["delete"]},
                            }
                        },
                    },
                }
            },
        }
        self.assertEqual(
            analyze_contract(schema, [r("r", "$.users[*]", "delete")]), []
        )

    def test_prefix_items_positions(self):
        schema = {
            "type": "array",
            "prefixItems": [
                {"type": "string"},
                {"type": "string", "x-redaction": {"actions": ["delete"]}},
            ],
        }
        self.assertEqual(analyze_contract(schema, [r("r", "$[1]", "delete")]), [])
        self.assertEqual(analyze_contract(schema, [r("r", "$[*]", "delete")]), [])
        violations = analyze_contract(schema, [r("r", "$[0]", "delete")])
        self.assertEqual(kinds(violations), ["uncovered"])
        self.assertEqual(violations[0]["path"], "$[1]")
        self.assertEqual(violations[0]["witness"], ["", ""])

    def test_items_after_prefix_items_min_index(self):
        schema = {
            "type": "array",
            "prefixItems": [{"type": "string"}],
            "items": {"type": "string", "x-redaction": {"actions": ["mask"]}},
        }
        # 规则只盖下标 1（items 管辖域内），下标 2 起未覆盖
        violations = analyze_contract(schema, [r("r", "$[1]", "mask")])
        self.assertEqual(kinds(violations), ["uncovered"])
        self.assertEqual(violations[0]["path"], "$[2]")
        # 下标 0 由 prefixItems 管辖，规则 $[0] 管不到 items 域
        violations = analyze_contract(schema, [r("r", "$[0]", "mask")])
        self.assertEqual(kinds(violations), ["uncovered"])
        self.assertEqual(violations[0]["path"], "$[1]")


class GateBranchTest(unittest.TestCase):
    def test_anyof_each_branch_checked(self):
        schema = {
            "type": "object",
            "properties": {
                "acct": {
                    "anyOf": [
                        {
                            "type": "object",
                            "properties": {
                                "iban": {
                                    "type": "string",
                                    "x-redaction": {"actions": ["tokenize"]},
                                }
                            },
                        },
                        {
                            "type": "object",
                            "properties": {
                                "card": {
                                    "type": "string",
                                    "x-redaction": {"actions": ["mask"]},
                                }
                            },
                        },
                    ]
                }
            },
        }
        violations = analyze_contract(schema, [r("r", "$.acct.iban", "tokenize")])
        self.assertEqual(kinds(violations), ["uncovered"])
        v = violations[0]
        self.assertEqual(v["path"], "$.acct.card")
        self.assertEqual(
            v["branch"],
            [{"keyword": "anyOf", "index": 1, "schema_path": "#/properties/acct"}],
        )
        self.assertEqual(v["witness"], {"acct": {"card": ""}})

    def test_oneof_branch(self):
        schema = {
            "oneOf": [
                {"type": "string"},
                {
                    "type": "object",
                    "properties": {
                        "s": {"type": "string", "x-redaction": {"actions": ["delete"]}}
                    },
                },
            ]
        }
        self.assertEqual(analyze_contract(schema, [r("r", "$.s", "delete")]), [])
        violations = analyze_contract(schema, [])
        self.assertEqual(kinds(violations), ["uncovered"])

    def test_allof_merges_constraints(self):
        schema = {
            "allOf": [
                {
                    "type": "object",
                    "properties": {
                        "a": {"type": "string", "x-redaction": {"actions": ["mask"]}}
                    },
                },
                {
                    "type": "object",
                    "required": ["b"],
                    "properties": {"b": {"type": "integer"}},
                },
            ]
        }
        violations = analyze_contract(schema, [])
        self.assertEqual(kinds(violations), ["uncovered"])
        v = violations[0]
        self.assertEqual(v["path"], "$.a")
        # witness 含 allOf 各分支的 required 兄弟
        self.assertEqual(v["witness"], {"a": "", "b": 0})
        self.assertEqual(analyze_contract(schema, [r("r", "$.a", "mask")]), [])

    def test_unsatisfiable_branch_pruned(self):
        schema = {
            "allOf": [
                {"type": "string"},
                {
                    "type": "object",
                    "properties": {
                        "a": {"x-redaction": {"actions": ["mask"]}}
                    },
                },
            ]
        }
        self.assertEqual(analyze_contract(schema, []), [])

    def test_ref_expansion(self):
        schema = {
            "$defs": {
                "secret": {"type": "string", "x-redaction": {"actions": ["tokenize"]}}
            },
            "type": "object",
            "properties": {
                "a": {"$ref": "#/$defs/secret"},
                "b": {"$ref": "#/$defs/secret"},
            },
        }
        violations = analyze_contract(schema, [r("r", "$.a", "tokenize")])
        self.assertEqual(kinds(violations), ["uncovered"])
        self.assertEqual(violations[0]["path"], "$.b")
        self.assertEqual(violations[0]["schema_path"], "#/$defs/secret")
        self.assertEqual(
            analyze_contract(
                schema, [r("r", "$.a", "tokenize"), r("r2", "$.b", "tokenize")]
            ),
            [],
        )

    def test_ref_with_siblings_intersects(self):
        schema = {
            "$defs": {"base": {"properties": {"a": {"type": "string"}}}},
            "type": "object",
            "properties": {
                "x": {
                    "$ref": "#/$defs/base",
                    "properties": {
                        "a": {"x-redaction": {"actions": ["mask"]}}
                    },
                }
            },
        }
        violations = analyze_contract(schema, [])
        self.assertEqual(kinds(violations), ["uncovered"])
        self.assertEqual(violations[0]["path"], "$.x.a")


class GateAdditionalPropertiesTest(unittest.TestCase):
    SCHEMA = {
        "type": "object",
        "properties": {"id": {"type": "integer"}},
        "additionalProperties": {
            "type": "string",
            "x-redaction": {"actions": ["mask"]},
        },
    }

    def test_concrete_key_rule_cannot_cover_all_keys(self):
        violations = analyze_contract(self.SCHEMA, [r("r", "$.secret", "mask")])
        self.assertEqual(kinds(violations), ["uncovered"])
        v = violations[0]
        # 任意键用不在 properties/规则中的全新键展示
        self.assertTrue(v["path"].startswith("$."))
        self.assertNotEqual(v["path"], "$.secret")
        self.assertNotEqual(v["path"], "$.id")

    def test_ancestor_rule_covers_any_key(self):
        schema = {
            "type": "object",
            "additionalProperties": {
                "type": "string",
                "x-redaction": {"actions": ["delete"]},
            },
        }
        self.assertEqual(analyze_contract(schema, [r("r", "$", "delete")]), [])

    def test_additional_properties_false_blocks_any_key(self):
        schema = {
            "type": "object",
            "properties": {"id": {"type": "integer"}},
            "additionalProperties": False,
        }
        self.assertEqual(analyze_contract(schema, []), [])


class GateWitnessTest(unittest.TestCase):
    def test_witness_minimal_with_required_siblings(self):
        schema = {
            "type": "object",
            "required": ["ts"],
            "properties": {
                "ts": {"type": "integer"},
                "user": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {
                        "id": {"type": "integer"},
                        "name": {
                            "type": "string",
                            "x-redaction": {"actions": ["mask"]},
                        },
                    },
                },
            },
        }
        violations = analyze_contract(schema, [])
        self.assertEqual(len(violations), 1)
        self.assertEqual(
            violations[0]["witness"],
            {"ts": 0, "user": {"id": 0, "name": ""}},
        )

    def test_violations_sorted_by_path_length(self):
        schema = {
            "type": "object",
            "properties": {
                "deep": {
                    "type": "object",
                    "properties": {
                        "x": {"x-redaction": {"actions": ["mask"]}}
                    },
                },
                "top": {"x-redaction": {"actions": ["mask"]}},
            },
        }
        violations = analyze_contract(schema, [])
        self.assertEqual([v["path"] for v in violations], ["$.top", "$.deep.x"])


if __name__ == "__main__":
    unittest.main()
