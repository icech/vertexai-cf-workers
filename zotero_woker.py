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

    // 对于 ChatGPT 端点，检查 Authorization: Bearer
    if (normalizedPathname === "/v1/chat/completions") {
        const authHeader = request.headers.get('Authorization');
        if (authHeader && authHeader.startsWith('Bearer ')) {
            apiKey = authHeader.split('Bearer ')[1].trim();
        }
    }

    // 如果没有找到 Bearer token，或者不是 ChatGPT 端点，回退到 x-api-key
    if (!apiKey) {
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
            case "/v1/v1/messages":
            case "/v1/messages":
            case "/messages":
                return handleMessagesEndpoint(request, token);
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


async function handleMessagesEndpoint(request, api_token) {
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

    // Handle system message if present
    let systemMessage = '';
    if (payload.messages && payload.messages.length > 0 && payload.messages[0].role === 'system') {
        systemMessage = payload.messages.shift().content;
    }

    // Transform ChatGPT request to Claude format
    const claudePayload = transformChatGPTToClaude(payload, systemMessage);

    // Use claude-3-5-sonnet@20240620 model
    const model = MODELS["claude-3-5-sonnet-20240620"];
    // Use claude-3-haiku@20240307 model
    // const model = MODELS["claude-3-haiku-20240307"];
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

        // 设置流式响应头
        const headers = new Headers({
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
        });

        const encoder = new TextEncoder();

        const stream = new ReadableStream({
            async start(controller) {
                const reader = response.body.getReader();
                let buffer = '';
                let fullResponse = '';

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;

                    const chunk = new TextDecoder().decode(value);
                    buffer += chunk;
                    fullResponse += chunk;
                    const events = buffer.split('\n\n');
                    buffer = events.pop() || '';

                    for (const event of events) {
                        if (event.trim() === '') continue;
                        const parsedEvent = parseSSEEvent(event);
                        if (parsedEvent) {
                            const encodedChunk = encoder.encode(`data: ${JSON.stringify(parsedEvent)}\n\n`);
                            controller.enqueue(encodedChunk);
                        }
                    }
                }

                console.log("Full Claude response:", fullResponse);

                // 发送结束事件
                const endEvent = encoder.encode(`data: ${JSON.stringify({choices: [{finish_reason: "stop"}]})}\n\n`);
                controller.enqueue(endEvent);
                controller.close();
            }
        });

        return new Response(stream, { headers });
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
                    choices: [{
                        delta: { content: parsed.delta.text },
                        finish_reason: null
                    }]
                };
            } else if (parsed.type === 'message_delta' && parsed.delta.stop_reason) {
                return {
                    choices: [{
                        delta: { content: '' },
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



function transformClaudeToChatGPT(claudeResponse, originalRequest) {
    let assistantMessage = '';
    let inputTokens = 0;
    let outputTokens = 0;
    let stopReason = 'stop';
    let parsedResponse = null;

    try {
        // Check if the response is SSE format
        if (claudeResponse.includes('event:')) {
            // Handle SSE format
            const events = claudeResponse.split('\n\n').filter(event => event.trim() !== '');
            for (const event of events) {
                const [eventType, eventData] = event.split('\n');
                if (eventData && eventData.startsWith('data: ')) {
                    const data = JSON.parse(eventData.slice(6));
                    
                    switch (data.type) {
                        case 'message_start':
                            inputTokens = data.message.usage.input_tokens;
                            break;
                        case 'content_block_delta':
                            assistantMessage += data.delta.text;
                            break;
                        case 'message_delta':
                            if (data.delta.stop_reason) {
                                stopReason = data.delta.stop_reason;
                            }
                            if (data.usage && data.usage.output_tokens) {
                                outputTokens = data.usage.output_tokens;
                            }
                            break;
                    }
                }
            }
        } else {
            // Handle JSON format
            parsedResponse = typeof claudeResponse === 'string' ? JSON.parse(claudeResponse) : claudeResponse;

            if (parsedResponse && parsedResponse.content && Array.isArray(parsedResponse.content)) {
                assistantMessage = parsedResponse.content
                    .filter(item => item.type === 'text')
                    .map(item => item.text)
                    .join('\n');
            }

            if (parsedResponse && parsedResponse.usage) {
                inputTokens = parsedResponse.usage.input_tokens || 0;
                outputTokens = parsedResponse.usage.output_tokens || 0;
            }

            stopReason = parsedResponse && parsedResponse.stop_reason ? parsedResponse.stop_reason : 'stop';
        }
    } catch (error) {
        console.error("Error parsing Claude response:", error);
        console.log("Raw Claude response:", claudeResponse);
        assistantMessage = "Sorry, there was an error processing the response.";
    }

    return {
        id: 'chatcmpl-' + Math.random().toString(36).substr(2, 9),
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        model: 'gpt-3.5-turbo', // We're mimicking GPT-3.5 Turbo here
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



function transformChatGPTToClaude(chatGPTPayload, systemMessage = '') {
    let claudeMessages = chatGPTPayload.messages.map(msg => ({
        role: msg.role === 'assistant' ? 'assistant' : 'user',
        content: msg.content
    }));

    // Prepend system message if present
    if (systemMessage) {
        claudeMessages.unshift({
            role: 'user',
            content: `System: ${systemMessage}\n\nHuman: ${claudeMessages[0].content}`
        });
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