"""M17 (hosted MCP, design audit gap #10): a hosted Streamable HTTP MCP
server at /mcp, so Claude, ChatGPT, and other MCP clients can reach the
public Literature AI API without each needing their own local stdio
process (omnibioai-sdk's omnibioai/mcp_server.py, which already exists
for that local case and is unaffected by this module).

Every tool call here is a loopback HTTP call into this same gateway's
own, already-complete /v1/literature/* REST routes (app/routes/v1.py),
carrying the caller's own omni_sk_ key as its Authorization header --
exactly the request shape a direct REST caller would send. This reuses
100% of the existing rate-limit, quota, idempotency, test-mode, BYOK,
and billing logic unchanged; nothing about metering or authorization is
reimplemented for this second transport.

See app/services/mcp_auth.py's own module docstring for why this does
not use the `mcp` SDK's OAuth-flavored auth subsystem, and this
milestone's checkpoint note for what a full OAuth 2.1 "connector" flow
would still need beyond what's built here.
"""
from mcp.server.mcpserver import MCPServer

from app.core.config import Config
from app.routes.gateway import proxy
from app.services.mcp_auth import get_current_mcp_api_key

SERVER_NAME = "omnibioai"
INSTRUCTIONS = (
    "Biomedical literature tools backed by PubMed, billed through the caller's own "
    "OmniBioAI organization. Use answer_with_citations for questions that need an "
    "evidence-based answer; every claim carries its PubMed ID. Use search_literature "
    "when only ranked source documents are needed, and list_domains to see which "
    "research domains can be searched."
)


class MCPToolCallError(RuntimeError):
    """Raised when the loopback REST call this tool wraps fails -- the
    MCP framework surfaces this to the calling client as a tool error,
    not a crashed session."""


async def _call_self(path: str, method: str, body: dict | None = None) -> dict:
    token = get_current_mcp_api_key()
    if not token:
        # Should be unreachable: MCPBearerAuthASGIMiddleware already
        # rejected any request without one before this ever runs. A
        # defensive backstop, not the primary check.
        raise MCPToolCallError("No authenticated API key for this MCP session.")
    status, response = await proxy.forward(
        url=f"{Config.SELF_BASE_URL}{path}",
        method=method,
        headers={"Authorization": f"Bearer {token}"},
        body=body,
    )
    if not 200 <= status < 300:
        error = response.get("error") if isinstance(response, dict) else response
        raise MCPToolCallError(f"OmniBioAI API error ({status}): {error}")
    return response


def build_mcp_server() -> MCPServer:
    server = MCPServer(SERVER_NAME, instructions=INSTRUCTIONS)

    @server.tool(description="Answer a biomedical question from PubMed abstracts, citing PMIDs. Billed per answer.")
    async def answer_with_citations(question: str, domain: str = "default") -> dict:
        return await _call_self("/v1/literature/answers", "POST", {"question": question, "domain": domain})

    @server.tool(
        description="Return ranked PubMed studies relevant to a question, with no generated answer -- "
                    "retrieval only. Billed per call, at a lower rate than an answer."
    )
    async def search_literature(question: str, domain: str = "default") -> dict:
        return await _call_self("/v1/literature/search", "POST", {"question": question, "domain": domain})

    @server.tool(description="List the research domains that can be searched. Free.")
    async def list_domains() -> dict:
        return await _call_self("/v1/literature/domains", "GET")

    return server
