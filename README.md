# mcp-oauth-tiers

`mcp-oauth-tiers` is a small, zero-dependency Python library for two easy-to-get-wrong edges of an MCP integration:

- generating and validating RFC 7636 PKCE code verifiers and deriving S256 challenges;
- applying an explicit, fail-closed policy to public and authenticated-user MCP tools.

It is a standalone clean-room companion project for the HoldDesk Amazon hackathon work, rather than a renamed copy of HoldDesk.

## Install

```console
python -m pip install .
```

Python 3.10 or newer is required.

## PKCE S256

```python
from mcp_oauth_tiers import generate_verifier, s256_challenge

verifier = generate_verifier()       # keep this in the client transaction state
challenge = s256_challenge(verifier) # send with code_challenge_method=S256
```

`generate_verifier()` uses `secrets` and defaults to 64 RFC 7636 unreserved characters. `s256_challenge()` rejects malformed verifiers before hashing them.

These helpers are stateless. They do not store authorization transactions, bind a verifier to a request, consume a verifier, or detect replay. Those lifecycle checks belong in the OAuth client and authorization server.

## MCP public and user tiers

```python
from mcp_oauth_tiers import ToolScopePolicy, visible_tool_metadata

policy = ToolScopePolicy(
    public_tools={"search_catalog"},
    user_tools={
        "read_booking": {"booking:read"},
        "cancel_booking": {"booking:read", "booking:write"},
    },
)

# `principal` and `granted_scopes` came from your already-validated token.
decision = policy.authorize(
    "cancel_booking",
    principal={"sub": "user-123"},
    granted_scopes={"booking:read", "booking:write"},
)
if not decision.allowed:
    raise PermissionError(decision.reason)
```

Unknown tools are always denied. A user-tier tool needs a non-`None` principal and every configured scope. The package deliberately treats the principal as opaque: the authentication layer owns its meaning.

Discovery metadata can be reduced for a caller:

```python
visible = visible_tool_metadata(
    server.list_tools(),
    policy,
    principal=validated_principal,
    granted_scopes=validated_scopes,
)
```

Metadata filtering is a user-interface convenience, not an authenticator or an execution guard. Tool metadata can be stale, bypassed, or forged. Call `policy.authorize(...)` again in the actual tool execution path.

## Security boundary

This library accepts already-validated scopes and a principal. It does **not**:

- authenticate or validate access tokens;
- host an OAuth authorization server;
- implement a complete OAuth security profile or transaction lifecycle;
- guarantee Alexa or Alexa+ certification.

The integrating application remains responsible for TLS, issuer and audience checks, token signature and expiry validation, redirect URI handling, state and nonce handling where applicable, PKCE transaction storage and one-time use, client security, authorization server behavior, MCP transport security, and authorization at execution time.

## Test

```console
PYTHONPATH=src python -m unittest discover -s tests -v
```

The tests include the RFC 7636 S256 example, verifier boundary and malformed-input cases, random verifier independence, fail-closed unknown tools, missing principals/scopes, and metadata filtering behavior.

## License

MIT © 2026 Alan Wen. See [LICENSE](LICENSE).
