# Entra Identity Posture MCP

An Agentic Security and Governance [MCP](https://modelcontextprotocol.io/) server built with **fastMCP** and the **Microsoft Graph API** for auditing and monitoring Microsoft Entra Identity Posture, Conditional Access, and Zero Trust posture.

> **Status:** Alpha — under active development. Interfaces and tool surfaces may change.

## Overview

This server exposes Microsoft Entra ID (Azure AD) security and governance data as MCP tools/resources so that AI agents (e.g., Claude Desktop, VS Code Copilot Chat) can:

- Audit Conditional Access policies for coverage gaps and misconfigurations
- Review identity posture signals (risky users/sign-ins, legacy auth, MFA coverage)
- Assess alignment against Zero Trust principles
- Generate human-readable governance reports

## Requirements

- Python 3.12+
- A Microsoft Entra ID app registration with permissions to read the relevant Microsoft Graph API resources (e.g., `Policy.Read.All`, `IdentityRiskyUser.Read.All`, `Directory.Read.All`, depending on which tools you use)

## Installation

Using [uv](https://docs.astral.sh/uv/) (recommended):

```bash
uv sync
```

Using pip:

```bash
pip install -e .
```

For development (includes test and lint tooling):

```bash
uv sync --group dev
```

## Configuration

The server authenticates to Microsoft Graph via [MSAL](https://learn.microsoft.com/entra/msal/python/). Provide your app registration credentials via environment variables:

| Variable              | Description                                      |
| --------------------- | ------------------------------------------------ |
| `ENTRA_TENANT_ID`     | Your Microsoft Entra tenant ID                   |
| `ENTRA_CLIENT_ID`     | Application (client) ID of your app registration |
| `ENTRA_CLIENT_SECRET` | Client secret for the app registration           |

> Update this table as configuration options are finalized.

## Usage

Run the MCP server directly:

```bash
entra-posture-mcp
```

Or configure it as an MCP server in your client (e.g., in VS Code `mcp.json` or Claude Desktop's config):

```jsonc
{
  "servers": {
    "entra-identity-posture": {
      "command": "entra-posture-mcp",
    },
  },
}
```

## Development

Run tests:

```bash
pytest
```

Lint and format:

```bash
ruff check .
ruff format .
```

## License

MIT © [Henry Mbugua](https://github.com/henrymbuguakiarie)
