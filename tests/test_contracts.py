"""受限 JSON Schema Draft 2020-12 契约编译器/校验器测试（纯标准库）。"""
import unittest

from app.contracts import (
    ContractSchemaError,
    compile_contract,
    instance_valid,
)


class CompileRejectTest(unittest.TestCase):
    def _reject(self, doc, needle=""):
        with self.assertRaises(ContractSchemaError) as cm:
            compile_contract(doc)
        self.assertTrue(
            needle in cm.exception.reason or needle in cm.exception.pointer,
            f"{needle!r} not in {cm.exception}",
        )

    def test_rejects_unsupported_keywords(self):
        for doc in (
            {"type": "number", "minimum": 1},
            {"enum": [1, 2]},
            {"type": "string", "format": "email"},
            {"type": "string", "pattern": "^x"},
            {"const": 1},
            {"type": "object", "propertyNames": True},
            {"type": "array", "contains": {"type": "string"}},
            {"$anchor": "a"},
        ):
            self._reject(doc)

    def test_rejects_bad_metaschema(self):
        self._reject(
            {"$schema": "http://json-schema.org/draft-07/schema#"},
            "Draft 2020-12",
        )

    def test_accepts_draft_metaschema(self):
        compile_contract(
            {"$schema": "https://json-schema.org/draft/2020-12/schema",
             "type": "null"}
        )

    def test_rejects_non_local_refs(self):
        self._reject({"$ref": "https://example.com/s"}, "local")
        self._reject({"$ref": "#/properties/x"}, "local")
        self._reject({"$ref": "other.json#"}, "local")

    def test_rejects_dangling_ref(self):
        self._reject({"$defs": {"a": True}, "$ref": "#/$defs/missing"}, "dangling")

    def test_accepts_local_refs_and_cycles(self):
        s = compile_contract(
            {
                "$defs": {
                    "node": {
                        "type": "object",
                        "properties": {"next": {"$ref": "#/$defs/node"}},
                    }
                },
                "$ref": "#/$defs/node",
            }
        )
        self.assertEqual(s.schema_path(s.root), "#")
        compile_contract({"$ref": "#"})

    def test_type_validation(self):
        self._reject({"type": "strng"}, "type")
        self._reject({"type": []}, "type")
        self._reject({"type": ["string", "string"]}, "type")
        s = compile_contract({"type": ["string", "null"]})
        self.assertTrue(instance_valid(s.root, "x"))
        self.assertTrue(instance_valid(s.root, None))
        self.assertFalse(instance_valid(s.root, 1))

    def test_integer_vs_number(self):
        s = compile_contract({"type": "integer"})
        self.assertTrue(instance_valid(s.root, 3))
        self.assertFalse(instance_valid(s.root, True))
        self.assertFalse(instance_valid(s.root, 3.5))

    def test_redaction_shape(self):
        self._reject({"x-redaction": {"actions": ["drop"]}}, "actions")
        self._reject({"x-redaction": {"actions": []}}, "actions")
        self._reject(
            {"x-redaction": {"actions": ["mask"], "extra": 1}},
            "x-redaction",
        )
        self._reject({"x-redaction": {"actions": "mask"}}, "x-redaction")
        self._reject(
            {"x-redaction": {"actions": ["mask", "mask"]}}, "actions"
        )
        s = compile_contract({"x-redaction": {"actions": ["delete", "mask"]}})
        self.assertEqual(s.root.actions, frozenset({"delete", "mask"}))

    def test_structure_checks(self):
        self._reject({"required": ["a", "a"]}, "required")
        self._reject({"required": "a"}, "required")
        self._reject({"properties": []}, "properties")
        self._reject({"allOf": {}}, "allOf")
        self._reject({"oneOf": [{"type": 1}]}, "oneOf")
        self._reject({"items": [{"type": "string"}]}, "items")
        self._reject({"prefixItems": {"type": "string"}}, "prefixItems")
        self._reject({"$defs": []}, "$defs")
        self._reject("notschema", "object")

    def test_boolean_schemas(self):
        s = compile_contract(True)
        self.assertTrue(instance_valid(s.root, {"anything": 1}))
        s2 = compile_contract(False)
        self.assertFalse(instance_valid(s2.root, {}))


class InstanceValidationTest(unittest.TestCase):
    def test_properties_required_additional(self):
        s = compile_contract(
            {
                "type": "object",
                "properties": {"a": {"type": "string"}},
                "required": ["a"],
                "additionalProperties": False,
            }
        )
        self.assertTrue(instance_valid(s.root, {"a": "x"}))
        self.assertFalse(instance_valid(s.root, {}))
        self.assertFalse(instance_valid(s.root, {"a": "x", "b": 1}))
        self.assertFalse(instance_valid(s.root, {"a": 1}))

    def test_array_tuple_and_items(self):
        s = compile_contract(
            {"type": "array", "prefixItems": [{"type": "string"}],
             "items": {"type": "integer"}}
        )
        self.assertTrue(instance_valid(s.root, ["a", 1, 2]))
        self.assertFalse(instance_valid(s.root, [1, 2]))
        self.assertFalse(instance_valid(s.root, ["a", "b"]))

    def test_combinators(self):
        s = compile_contract(
            {"allOf": [{"type": "object"}, {"required": ["a"]}]}
        )
        self.assertTrue(instance_valid(s.root, {"a": 1}))
        self.assertFalse(instance_valid(s.root, {}))

        s = compile_contract(
            {"anyOf": [{"type": "string"}, {"type": "integer"}]}
        )
        self.assertTrue(instance_valid(s.root, "x"))
        self.assertTrue(instance_valid(s.root, 1))
        self.assertFalse(instance_valid(s.root, []))

        s = compile_contract(
            {"oneOf": [{"type": "string"}, {"type": "integer"}]}
        )
        self.assertTrue(instance_valid(s.root, "x"))
        self.assertFalse(instance_valid(s.root, []))


if __name__ == "__main__":
    unittest.main()
