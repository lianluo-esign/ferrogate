import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

const SDK_PACKAGE = '@modelcontextprotocol/client';
const SDK_VERSION = '2.0.0';
const SDK_COMMIT = 'cc4b41617ce3601b1290d67216ea0b194a3cd9ac';
const SPEC_COMMIT = '71e306956a4959c9655e5036be215d41986596e6';
const CANDIDATE_VERSION = '2026-07-28';

const endpoint = process.env.FERROGATE_MCP_OFFICIAL_ENDPOINT;
const secondaryEndpoint = process.env.FERROGATE_MCP_OFFICIAL_SECONDARY_ENDPOINT;
const token = process.env.FERROGATE_MCP_OFFICIAL_TOKEN;
if (!endpoint || !secondaryEndpoint || !token) {
    throw new Error(
        'FERROGATE_MCP_OFFICIAL_ENDPOINT, FERROGATE_MCP_OFFICIAL_SECONDARY_ENDPOINT, and FERROGATE_MCP_OFFICIAL_TOKEN are required'
    );
}

const drive = async (mode, label, endpoints) => {
    const wire = [];
    let rpcOrdinal = 0;
    const observedFetch = async (input, init = {}) => {
        const observedRequest = new Request(input, init);
        const headers = Object.fromEntries(observedRequest.headers.entries());
        if (headers.authorization) {
            headers.authorization = '<redacted>';
        }
        let body = null;
        const bodyText = await observedRequest.clone().text();
        if (bodyText.length > 0) {
            body = JSON.parse(bodyText);
        }
        const gatewayInstance = typeof body?.method === 'string'
            ? rpcOrdinal++ % endpoints.length
            : 0;
        const response = await fetch(new Request(endpoints[gatewayInstance], observedRequest));
        let responseBody = null;
        const responseText = await response.clone().text();
        if (responseText.length > 0) {
            try {
                responseBody = JSON.parse(responseText);
            } catch {
                responseBody = null;
            }
        }
        wire.push({
            gatewayInstance,
            httpMethod: observedRequest.method,
            headers,
            body,
            response: responseBody
        });
        return response;
    };

    const client = new Client(
        { name: `ferrogate-official-${label}`, version: '1.0.0' },
        { versionNegotiation: { mode } }
    );
    const transport = new StreamableHTTPClientTransport(new URL(endpoints[0]), {
        requestInit: { headers: { Authorization: `Bearer ${token}` } },
        fetch: observedFetch
    });

    await client.connect(transport);
    const tools = await client.listTools();
    const call = await client.callTool({
        name: 'http-search',
        arguments: { query: `ferrogate-official-${label}` }
    });
    const result = {
        era: client.getProtocolEra(),
        protocolVersion: client.getNegotiatedProtocolVersion(),
        tools: tools.tools.map(tool => tool.name),
        call,
        wire
    };
    await client.close();
    return result;
};

const modern = await drive('auto', 'modern', [endpoint, secondaryEndpoint]);
const legacy = await drive('legacy', 'legacy', [endpoint]);
process.stdout.write(
    JSON.stringify({
        opponent: {
            package: SDK_PACKAGE,
            version: SDK_VERSION,
            commit: SDK_COMMIT,
            protocolArtifactCommit: SPEC_COMMIT,
            protocolArtifactStatus: 'candidate'
        },
        candidateVersion: CANDIDATE_VERSION,
        modern,
        legacy
    })
);
