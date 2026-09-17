import unittest

from app.contractschema import SchemaError, validate_contract_schema


def ok(schema):
    validate_contract_schema(schema)


def bad(schema):
    try:
        validate_contract_schema(schema)
    except SchemaError:
        return
    raise AssertionError(f"schema should be rejected: {schema!r}")


class ContractSchemaTest(unittest.TestCase):
    def test_minimal_valid(self):
        ok({})
        ok(True)
        ok(False)
        ok({"type": "object"})
        ok({"$schema": "https://json-schema.org/draft/2020-12/schema"})

    def test_all_supported_keywords(self):
        ok(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$defs": {"s": {"type": "string"}},
                "type": ["object", "null"],
                "properties": {"a": {"$ref": "#/$defs/s"}},
                "required": ["a"],
                "additionalProperties": False,
                "items": {"type": "string"},
                "prefixItems": [{"type": "string"}],
                "allOf": [{"type": "object"}],
                "anyOf": [{"type": "object"}, {"type": "null"}],
                "oneOf": [{"type": "object"}, {"type": "null"}],
                "x-redaction": {"actions": ["delete", "mask", "tokenize"]},
            }
        )

    def test_unsupported_keywords_rejected(self):
        for kw in (
            "pattern", "format", "enum", "const", "minimum", "maxLength",
            "minItems", "uniqueItems", "patternProperties", "dependentRequired",
            "contains", "not", "if", "then", "else", "$id", "$anchor",
            "$dynamicRef", "title", "description", "default", "examples",
            "readOnly", "deprecated", "propertyNames", "minProperties",
        ):
            bad({kw: "x"} if kw not in ("enum", "const") else {kw: ["a"]})

    def test_type_values(self):
        ok({"type": "string"})
        ok({"type": ["string", "integer", "boolean", "null"]})
        bad({"type": "text"})
        bad({"type": []})
        bad({"type": ["string", "string"]})
        bad({"type": 3})

    def test_redaction_extension(self):
        ok({"x-redaction": {"actions": ["mask"]}})
        bad({"x-redaction": {"actions": []}})
        bad({"x-redaction": {"actions": ["encrypt"]}})
        bad({"x-redaction": {"actions": ["mask", "mask"]}})
        bad({"x-redaction": {"actions": "mask"}})
        bad({"x-redaction": {"actions": ["mask"], "extra": 1}})
        bad({"x-redaction": {}})

    def test_required_and_combinators_shape(self):
        bad({"required": "a"})
        bad({"required": ["a", "a"]})
        bad({"allOf": []})
        bad({"anyOf": {}})
        bad({"oneOf": "x"})
        bad({"prefixItems": {"0": {}}})
        bad({"properties": []})

    def test_ref_must_be_local(self):
        bad({"$ref": "https://example.com/s.json"})
        bad({"$ref": "other.json#/defs/x"})
        bad({"$ref": 3})
        ok({"$defs": {"a": {"type": "string"}}, "$ref": "#/$defs/a"})

    def test_ref_must_resolve(self):
        bad({"$ref": "#/$defs/missing", "$defs": {}})
        bad({"$ref": "#/properties/nope"})

    def test_ref_target_must_be_schema(self):
        # 指向非 schema 位置（字符串/数组/annotation 值）一律拒绝
        bad({"required": ["a"], "properties": {"a": {"$ref": "#/required/0"}}})
        bad({"x-redaction": {"actions": ["mask"]}, "$defs": {"x": {"$ref": "#/x-redaction"}}})
        ok({"$defs": {"a": {"type": "string"}}, "properties": {"x": {"$ref": "#/$defs/a"}}})

    def test_root_self_ref_is_cyclic(self):
        bad({"$ref": "#"})

    def test_direct_and_indirect_cycles_rejected(self):
        bad({"$defs": {"a": {"$ref": "#/$defs/a"}}, "$ref": "#/$defs/a"})
        bad(
            {
                "$defs": {
                    "a": {"properties": {"n": {"$ref": "#/$defs/b"}}},
                    "b": {"items": {"$ref": "#/$defs/a"}},
                },
                "$ref": "#/$defs/a",
            }
        )

    def test_acyclic_ref_dag_accepted(self):
        ok(
            {
                "$defs": {
                    "a": {"type": "string"},
                    "b": {"$ref": "#/$defs/a"},
                    "c": {"properties": {"x": {"$ref": "#/$defs/b"}}},
                },
                "properties": {
                    "p": {"$ref": "#/$defs/c"},
                    "q": {"$ref": "#/$defs/a"},
                },
            }
        )

    def test_nested_schema_positions_validated(self):
        bad({"properties": {"a": {"pattern": "x"}}})
        bad({"items": {"minimum": 1}})
        bad({"allOf": [{"enum": [1]}]})
        bad({"$defs": {"a": {"format": "email"}}})
        ok({"additionalProperties": {"type": "string"}})
        ok({"additionalProperties": True})

    def test_nesting_depth_bounded(self):
        node = {}
        root = node
        for _ in range(200):
            node["properties"] = {"x": {}}
            node = node["properties"]["x"]
        bad(root)  # 超深嵌套必须被拒绝而不是耗尽显式递归


if __name__ == "__main__":
    unittest.main()
