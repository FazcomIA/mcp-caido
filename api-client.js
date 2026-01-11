import fetch from 'node-fetch';
import 'dotenv/config';

const CAIDO_URL = process.env.CAIDO_URL || 'http://127.0.0.1:8080/graphql';
const CAIDO_API_TOKEN = process.env.CAIDO_API_TOKEN;

if (!CAIDO_API_TOKEN) {
  console.warn("⚠️ WARNING: CAIDO_API_TOKEN is not set. Requests to Caido will likely fail.");
}

async function query(query, variables = {}) {
  try {
    const response = await fetch(CAIDO_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${CAIDO_API_TOKEN}`,
        'User-Agent': 'Caido-MCP-Server/1.0'
      },
      body: JSON.stringify({ query, variables })
    });

    if (!response.ok) {
      throw new Error(`HTTP Error: ${response.status} ${response.statusText}`);
    }

    const result = await response.json();

    if (result.errors) {
      const errorMsg = result.errors.map(e => e.message).join(', ');
      throw new Error(`GraphQL Error: ${errorMsg}`);
    }

    return result.data;
  } catch (error) {
    console.error(`[Caido API] Query failed:`, error.message);
    throw error;
  }
}

// =========================================
// Operations
// =========================================

export async function createRequest(url, method = 'GET', headers = {}, body = '') {
  // Parsing URL to get host, port, scheme, path
  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    throw new Error(`Invalid URL: ${url}`);
  }

  const host = parsed.hostname;
  const port = parsed.port ? parseInt(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80);
  const scheme = parsed.protocol.replace(':', '');
  const path = parsed.pathname + parsed.search;

  // Construct raw request (simplified)
  let rawHeaders = '';
  Object.entries(headers).forEach(([k, v]) => {
    rawHeaders += `${k}: ${v}\r\n`;
  });

  // Basic raw request construction
  const rawRequest = `${method} ${path} HTTP/1.1\r\nHost: ${host}\r\n${rawHeaders}\r\n${body}`;

  const mutation = `
    mutation CreateRequest($input: CreateRequestInput!) {
      createRequest(input: $input) {
        request {
          id
        }
      }
    }
  `;

  // Note: Depending on Caido version, input structure might vary. 
  // This assumes standard CreateRequestInput.
  const variables = {
    input: {
      connection: {
        host,
        port,
        isTls: scheme === 'https'
      },
      raw: Buffer.from(rawRequest).toString('base64'),
    }
  };

  return query(mutation, variables);
}

export async function getFindings(limit = 20) {
  const q = `
    query GetFindings($first: Int) {
      findings(first: $first) {
        edges {
          node {
            id
            title
            description
            reporter
            createdAt
            request {
              host
              path
            }
          }
        }
      }
    }
  `;
  return query(q, { first: limit });
}

export async function getRequestHistory(limit = 20) {
  const q = `
    query GetRequests($first: Int) {
      requests(first: $first) {
        edges {
          node {
            id
            host
            method
            path
            query
            response {
              statusCode
              roundtripTime
            }
          }
        }
      }
    }
  `;
  return query(q, { first: limit });
}

export default {
  query,
  createRequest,
  getFindings,
  getRequestHistory
};
