import unittest

from mcp_oauth_tiers import ToolScopePolicy, visible_tool_metadata


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = ToolScopePolicy(
            public_tools={"search_catalog"},
            user_tools={
                "read_booking": {"booking:read"},
                "cancel_booking": {"booking:read", "booking:write"},
            },
        )

    def test_public_tool_needs_no_principal(self):
        decision = self.policy.authorize("search_catalog")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "public_tool")

    def test_unknown_tool_fails_closed_even_with_broad_scope(self):
        decision = self.policy.authorize(
            "admin_everything", principal={"sub": "user-1"}, granted_scopes={"*"}
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "unknown_tool")
        self.assertEqual(self.policy.authorize(None).reason, "unknown_tool")  # type: ignore[arg-type]
        self.assertEqual(self.policy.authorize([]).reason, "unknown_tool")  # type: ignore[arg-type]

    def test_user_tool_needs_principal_and_all_scopes(self):
        no_principal = self.policy.authorize(
            "read_booking", granted_scopes={"booking:read"}
        )
        self.assertEqual(no_principal.reason, "missing_principal")

        missing_scope = self.policy.authorize(
            "cancel_booking",
            principal={"sub": "user-1"},
            granted_scopes={"booking:write"},
        )
        self.assertEqual(missing_scope.reason, "missing_scopes")

        allowed = self.policy.authorize(
            "cancel_booking",
            principal={"sub": "user-1"},
            granted_scopes={"booking:write", "booking:read", "extra"},
        )
        self.assertTrue(allowed.allowed)

    def test_empty_but_validated_principal_object_is_present(self):
        self.assertTrue(
            self.policy.authorize(
                "read_booking", principal={}, granted_scopes={"booking:read"}
            ).allowed
        )

    def test_metadata_filter_omits_malformed_and_unknown_entries(self):
        tools = [
            {"name": "search_catalog"},
            {"name": "read_booking"},
            {"name": "cancel_booking"},
            {"name": "surprise"},
            {"description": "missing name"},
        ]
        visible = visible_tool_metadata(
            tools,
            self.policy,
            principal="validated-user-1",
            granted_scopes={"booking:read"},
        )
        self.assertEqual(
            [item["name"] for item in visible],
            ["search_catalog", "read_booking"],
        )

    def test_invalid_policy_is_rejected(self):
        with self.assertRaises(TypeError):
            ToolScopePolicy(public_tools="search_catalog")
        with self.assertRaises(ValueError):
            ToolScopePolicy(public_tools={"same"}, user_tools={"same": {"read"}})
        with self.assertRaises(ValueError):
            ToolScopePolicy(user_tools={"unsafe": set()})
        with self.assertRaises(ValueError):
            ToolScopePolicy(user_tools={"": {"read"}})
        with self.assertRaises(TypeError):
            self.policy.authorize(
                "read_booking", principal="user", granted_scopes="booking:read"
            )


if __name__ == "__main__":
    unittest.main()
