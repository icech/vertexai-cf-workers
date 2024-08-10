const MODELS = {
    "claude-3-opus": {
        vertexName: "claude-3-opus@20240229",
        region: "us-east5",
    },
    "claude-3-sonnet": {
        vertexName: "claude-3-sonnet@20240229",
        region: "us-central1",
    },
    "claude-3-haiku": {
        vertexName: "claude-3-haiku@20240307",
        region: "us-central1",
    },
    "claude-3-5-sonnet": {
        vertexName: "claude-3-5-sonnet@20240620",
        region: "us-east5",
    },
    "claude-3-opus-20240229": {
        vertexName: "claude-3-opus@20240229",
        region: "us-east5",
    },
    "claude-3-sonnet-20240229": {
        vertexName: "claude-3-sonnet@20240229",
        region: "us-central1",
    },
    "claude-3-haiku-20240307": {
        vertexName: "claude-3-haiku@20240307",
        region: "us-central1",
    },
    "claude-3-5-sonnet-20240620": {
        vertexName: "claude-3-5-sonnet@20240620",
        region: "us-east5",
    },
};

addEventListener("fetch", (event) => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    let headers = new Headers({
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    });
    if (request.method === "OPTIONS") {
        return new Response(null, { headers });
    } else if (request.method === "GET") {
        return createErrorResponse(405, "invalid_request_error", "GET method is not allowed");
    }

    let apiKey;
    const url = new URL(request.url);
    const normalizedPathname = url.pathname.replace(/^(\/)+/, '/');

    const authHeader = request.headers.get('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
        apiKey = authHeader.split('Bearer ')[1].trim();
    } else {
        apiKey = request.headers.get("x-api-key");
    }

    if (!API_KEY || API_KEY !== apiKey) {
        return createErrorResponse(401, "authentication_error", "Invalid API key");
    }

    const signedJWT = await createSignedJWT(CLIENT_EMAIL, PRIVATE_KEY)
    const [token, err] = await exchangeJwtForAccessToken(signedJWT)
    if (token === null) {
        console.log(`Invalid jwt token: ${err}`)
        return createErrorResponse(500, "api_error", "invalid authentication credentials");
    }

    try {
        switch(normalizedPathname) {
            case "/v1/messages":
            case "/messages":
                return handleClaudeMessagesEndpoint(request, token);
            case "/v1/chat/completions":
                return handleChatGPTEndpoint(request, token);
            default:
                return createErrorResponse(404, "not_found_error", "Not Found");
        }
    } catch (error) {
        console.error(error);
        return createErrorResponse(500, "api_error", "An unexpected error occurred");
    }
}

async function handleClaudeMessagesEndpoint(request, api_token) {
    const anthropicVersion = request.headers.get('anthropic-version');
    if (anthropicVersion && anthropicVersion !== '2023-06-01') {
        return createErrorResponse(400, "invalid_request_error", "API version not supported");
    }

    let payload;
    try {
        payload = await request.json();
    } catch (err) {
        return createErrorResponse(400, "invalid_request_error", "The request body is not valid JSON.");
    }

    payload.anthropic_version = "vertex-2023-10-16";

    if (!payload.model) {
        return createErrorResponse(400, "invalid_request_error", "Missing model in the request payload.");
    } else if (!MODELS[payload.model]) {
        return createErrorResponse(400, "invalid_request_error", `Model \`${payload.model}\` not found.`);
    }

    const stream = payload.stream || false;
    const model = MODELS[payload.model];
    const url = `https://${model.region}-aiplatform.googleapis.com/v1/projects/${PROJECT}/locations/${model.region}/publishers/anthropic/models/${model.vertexName}:streamRawPredict`;
    delete payload.model;

    let response, contentType
    try {
        response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${api_token}`
            },
            body: JSON.stringify(payload)
        });
        contentType = response.headers.get("Content-Type") || "application/json";
    } catch (error) {
        return createErrorResponse(500, "api_error", "Server Error");
    }

    if (stream && contentType.startsWith('text/event-stream')) {
        if (!(response.body instanceof ReadableStream)) {
            return createErrorResponse(500, "api_error", "Server Error");
        }

        const encoder = new TextEncoder();
        const decoder = new TextDecoder("utf-8");
        let buffer = '';
        let { readable, writable } = new TransformStream({
            transform(chunk, controller) {
                let decoded = decoder.decode(chunk, { stream: true });
                buffer += decoded
                let eventList = buffer.split(/\r\n\r\n|\r\r|\n\n/g);
                if (eventList.length === 0) return;
                buffer = eventList.pop();

                for (let event of eventList) {
                    controller.enqueue(encoder.encode(`${event}\n\n`));
                }
            },
        });
        response.body.pipeTo(writable);
        return new Response(readable, {
            status: response.status,
            headers: {
                "Content-Type": response.headers.get("Content-Type") || "text/event-stream",
                "Access-Control-Allow-Origin": "*",
            },
        });
    } else {
        try {
            let data = await response.text();
            return new Response(data, {
                status: response.status,
                headers: {
                    "Content-Type": contentType,
                    "Access-Control-Allow-Origin": "*",
                },
            });
        } catch (error) {
            return createErrorResponse(500, "api_error", "Server Error");
        }
    }
}

async function handleChatGPTEndpoint(request, api_token) {
    let payload;
    try {
        payload = await request.json();
    } catch (err) {
        console.error("Error parsing request body:", err);
        return createErrorResponse(400, "invalid_request_error", "The request body is not valid JSON.");
    }

    let systemMessage = '';
    if (payload.messages && payload.messages.length > 0 && payload.messages[0].role === 'system') {
        systemMessage = payload.messages.shift().content;
    }

    const claudePayload = transformChatGPTToClaude(payload, systemMessage);

    // Use claude-3-5-sonnet@20240620 model
    // const model = MODELS["claude-3-5-sonnet-20240620"];
    const model = MODELS["claude-3-haiku-20240307"];
    const url = `https://${model.region}-aiplatform.googleapis.com/v1/projects/${PROJECT}/locations/${model.region}/publishers/anthropic/models/${model.vertexName}:streamRawPredict`;

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${api_token}`
            },
            body: JSON.stringify(claudePayload)
        });

        if (!response.ok) {
            const errorData = await response.text();
            console.error("Claude API error. Status:", response.status, "Response:", errorData);
            return createErrorResponse(response.status, "api_error", "An error occurred while processing the request");
        }

        if (claudePayload.stream) {
            const { readable, writable } = new TransformStream();
            const writer = writable.getWriter();
            const encoder = new TextEncoder();

            (async () => {
                const reader = response.body.getReader();
                let buffer = '';
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    buffer += new TextDecoder().decode(value);
                    const events = buffer.split('\n\n');
                    buffer = events.pop();
                    for (const event of events) {
                        if (event.trim() === '') continue;
                        const parsedEvent = parseSSEEvent(event);
                        if (parsedEvent) {
                            await writer.write(encoder.encode(`data: ${JSON.stringify(parsedEvent)}\n\n`));
                        }
                    }
                }
                await writer.write(encoder.encode(`data: [DONE]\n\n`));
                await writer.close();
            })();

            return new Response(readable, {
                headers: {
                    'Content-Type': 'text/event-stream',
                    'Cache-Control': 'no-cache',
                    'Connection': 'keep-alive',
                    'Access-Control-Allow-Origin': '*',
                }
            });
        } else {
            const data = await response.json();
            const chatGPTResponse = transformClaudeToChatGPT(data, payload);
            return new Response(JSON.stringify(chatGPTResponse), {
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                }
            });
        }
    } catch (error) {
        console.error("Error in handleChatGPTEndpoint:", error);
        return createErrorResponse(500, "api_error", "An unexpected error occurred");
    }
}

function parseSSEEvent(event) {
    const lines = event.split('\n');
    const data = lines.find(line => line.startsWith('data: '));
    if (data) {
        try {
            const parsed = JSON.parse(data.slice(6));
            if (parsed.type === 'content_block_delta') {
                return {
                    id: 'chatcmpl-' + Math.random().toString(36).substr(2, 9),
                    object: 'chat.completion.chunk',
                    created: Math.floor(Date.now() / 1000),
                    model: 'gpt-3.5-turbo-0613',
                    choices: [{
                        index: 0,
                        delta: { content: parsed.delta.text },
                        finish_reason: null
                    }]
                };
            } else if (parsed.type === 'message_delta' && parsed.delta.stop_reason) {
                return {
                    id: 'chatcmpl-' + Math.random().toString(36).substr(2, 9),
                    object: 'chat.completion.chunk',
                    created: Math.floor(Date.now() / 1000),
                    model: 'gpt-3.5-turbo-0613',
                    choices: [{
                        index: 0,
                        delta: {},
                        finish_reason: parsed.delta.stop_reason
                    }]
                };
            }
        } catch (e) {
            console.error('Error parsing SSE event:', e);
        }
    }
    return null;
}

function transformChatGPTToClaude(chatGPTPayload, systemMessage = '') {
    let claudeMessages = [];
    let lastRole = null;

    for (let msg of chatGPTPayload.messages) {
        let role = msg.role === 'assistant' ? 'assistant' : 'user';
        let content = msg.content;

        if (msg.role === 'system') {
            if (claudeMessages.length === 0) {
                claudeMessages.push({
                    role: 'user',
                    content: `System: ${content}`
                });
            } else {
                let lastMsg = claudeMessages[claudeMessages.length - 1];
                if (lastMsg.role === 'user') {
                    lastMsg.content += `\n\nSystem: ${content}`;
                } else {
                    claudeMessages.push({
                        role: 'user',
                        content: `System: ${content}`
                    });
                }
            }
            continue;
        }

        if (role === lastRole) {
            let lastMsg = claudeMessages[claudeMessages.length - 1];
            lastMsg.content += `\n\n${role === 'user' ? 'Human' : 'Assistant'}: ${content}`;
        } else {
            claudeMessages.push({
                role: role,
                content: role === 'user' ? `Human: ${content}` : content
            });
        }

        lastRole = role;
    }

    return {
        anthropic_version: "vertex-2023-10-16",
        messages: claudeMessages,
        max_tokens: chatGPTPayload.max_tokens || 1024,
        temperature: chatGPTPayload.temperature || 0.7,
        top_p: chatGPTPayload.top_p || 1,
        stream: chatGPTPayload.stream || false
    };
}

function transformClaudeToChatGPT(claudeResponse, originalRequest) {
    let assistantMessage = '';
    let inputTokens = 0;
    let outputTokens = 0;
    let stopReason = 'stop';

    if (claudeResponse.content && Array.isArray(claudeResponse.content)) {
        assistantMessage = claudeResponse.content
            .filter(item => item.type === 'text')
            .map(item => item.text)
            .join('\n');
    }

    if (claudeResponse.usage) {
        inputTokens = claudeResponse.usage.input_tokens || 0;
        outputTokens = claudeResponse.usage.output_tokens || 0;
    }

    stopReason = claudeResponse.stop_reason || 'stop';

    return {
        id: 'chatcmpl-' + Math.random().toString(36).substr(2, 9),
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        model: 'gpt-3.5-turbo-0613',
        choices: [
            {
                index: 0,
                message: {
                    role: 'assistant',
                    content: assistantMessage
                },
                finish_reason: stopReason
            }
        ],
        usage: {
            prompt_tokens: inputTokens,
            completion_tokens: outputTokens,
            total_tokens: inputTokens + outputTokens
        }
    };
}



function createErrorResponse(status, errorType, message) {
    const errorObject = { type: "error", error: { type: errorType, message: message } };
    return new Response(JSON.stringify(errorObject), {
        status: status,
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
    });
}

async function createSignedJWT(email, pkey) {
    pkey = pkey.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\r|\n|\\n/g, "");
    let cryptoKey = await crypto.subtle.importKey(
        "pkcs8",
        str2ab(atob(pkey)),
        {
            name: "RSASSA-PKCS1-v1_5",
            hash: { name: "SHA-256" },
        },
        false,
        ["sign"]
    );

    const authUrl = "https://www.googleapis.com/oauth2/v4/token";
    const issued = Math.floor(Date.now() / 1000);
    const expires = issued + 600;

    const header = {
        alg: "RS256",
        typ: "JWT",
    };

    const payload = {
        iss: email,
        aud: authUrl,
        iat: issued,
        exp: expires,
        scope: "https://www.googleapis.com/auth/cloud-platform",
    };

    const encodedHeader = urlSafeBase64Encode(JSON.stringify(header));
    const encodedPayload = urlSafeBase64Encode(JSON.stringify(payload));

    const unsignedToken = `${encodedHeader}.${encodedPayload}`;

    const signature = await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        cryptoKey,
        str2ab(unsignedToken)
    );

    const encodedSignature = urlSafeBase64Encode(signature);
    return `${unsignedToken}.${encodedSignature}`;
}

async function exchangeJwtForAccessToken(signed_jwt) {
    const auth_url = "https://www.googleapis.com/oauth2/v4/token";
    const params = {
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: signed_jwt,
    };

    const r = await fetch(auth_url, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: Object.entries(params)
            .map(([k, v]) => k + "=" + v)
            .join("&"),
    }).then((res) => res.json());

    if (r.access_token) {
        return [r.access_token, ""];
    }

    return [null, JSON.stringify(r)];
}

function str2ab(str) {
    const buffer = new ArrayBuffer(str.length);
    let bufferView = new Uint8Array(buffer);
    for (let i = 0; i < str.length; i++) {
        bufferView[i] = str.charCodeAt(i);
    }
    return buffer;
}

function urlSafeBase64Encode(data) {
    let base64 = typeof data === "string" ? btoa(encodeURIComponent(data).replace(/%([0-9A-F]{2})/g, (match, p1) => String.fromCharCode(parseInt("0x" + p1)))) : btoa(String.fromCharCode(...new Uint8Array(data)));
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}