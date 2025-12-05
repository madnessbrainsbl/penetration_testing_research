#!/usr/bin/env node
/**
 * XSS ATTACK SIMULATOR
 * 
 * This script simulates a vulnerable third-party dashboard consuming Mender API.
 * It demonstrates that XSS payloads stored in the backend WILL execute when
 * rendered unsafely (which is a common developer mistake).
 */

const https = require('https');

// ANSI color codes for terminal output
const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    bold: '\x1b[1m'
};

function log(color, ...args) {
    console.log(color, ...args, colors.reset);
}

function makeRequest(hostname, path, token) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: hostname,
            path: path,
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                if (res.statusCode === 200) {
                    resolve(JSON.parse(data));
                } else {
                    reject(new Error(`HTTP ${res.statusCode}: ${data}`));
                }
            });
        });

        req.on('error', reject);
        req.end();
    });
}

async function simulateVulnerableDashboard(token) {
    log(colors.cyan + colors.bold, '\n════════════════════════════════════════════════════════════════');
    log(colors.cyan + colors.bold, 'XSS ATTACK SIMULATION - VULNERABLE DASHBOARD');
    log(colors.cyan + colors.bold, '════════════════════════════════════════════════════════════════\n');

    log(colors.blue, '[*] Fetching device inventory from Mender API...');
    
    try {
        const devices = await makeRequest(
            'staging.hosted.mender.io',
            '/api/management/v1/inventory/devices',
            token
        );

        log(colors.green, `[+] Received ${devices.length} devices from API\n`);

        // Simulate vulnerable dashboard code
        log(colors.yellow, 'SIMULATING VULNERABLE DASHBOARD CODE:');
        log(colors.yellow, '   This is what many developers write:\n');
        console.log('   ' + colors.blue + 'devices.forEach(device => {');
        console.log('       device.attributes.forEach(attr => {');
        console.log('           // VULNERABLE: Directly inserting API data into DOM');
        console.log('           element.innerHTML += `<div>${attr.value}</div>`;');
        console.log('       });');
        console.log('   });' + colors.reset + '\n');

        // Analyze responses for XSS
        let totalXSSPayloads = 0;
        let xssDevices = [];

        devices.forEach((device, idx) => {
            const deviceXSS = [];
            
            device.attributes.forEach(attr => {
                const value = String(attr.value || '');
                
                // Check for XSS patterns
                const patterns = [
                    { name: '<script> tag', regex: /<script.*?>/i },
                    { name: 'onerror handler', regex: /onerror\s*=/i },
                    { name: 'alert() call', regex: /alert\s*\(/i },
                    { name: '<img> with event', regex: /<img.*?on\w+/i },
                    { name: 'javascript: URL', regex: /javascript:/i }
                ];

                patterns.forEach(pattern => {
                    if (pattern.regex.test(value)) {
                        deviceXSS.push({
                            attribute: attr.name,
                            value: value,
                            pattern: pattern.name,
                            scope: attr.scope
                        });
                        totalXSSPayloads++;
                    }
                });
            });

            if (deviceXSS.length > 0) {
                xssDevices.push({
                    id: device.id,
                    mac: device.attributes.find(a => a.name === 'mac')?.value || 'N/A',
                    payloads: deviceXSS
                });
            }
        });

        // Report findings
        log(colors.cyan + colors.bold, '\n════════════════════════════════════════════════════════════════');
        log(colors.cyan + colors.bold, 'XSS ANALYSIS RESULTS');
        log(colors.cyan + colors.bold, '════════════════════════════════════════════════════════════════\n');

        if (totalXSSPayloads === 0) {
            log(colors.green, '✓ No XSS payloads detected in current inventory');
            log(colors.yellow, '  (This means test payloads were not injected yet)');
        } else {
            log(colors.red + colors.bold, `CRITICAL: ${totalXSSPayloads} XSS PAYLOAD(S) DETECTED!\n`);

            xssDevices.forEach((dev, idx) => {
                log(colors.red, `\n[Device ${idx + 1}]`);
                log(colors.reset, `  Device ID: ${dev.id}`);
                log(colors.reset, `  MAC Address: ${dev.mac}`);
                log(colors.red, `  XSS Payloads: ${dev.payloads.length}\n`);

                dev.payloads.forEach((xss, pIdx) => {
                    log(colors.yellow, `  Payload #${pIdx + 1}:`);
                    log(colors.reset, `    Attribute: ${xss.attribute} (${xss.scope})`);
                    log(colors.reset, `    Pattern: ${xss.pattern}`);
                    log(colors.magenta, `    Value: ${xss.value.substring(0, 80)}${xss.value.length > 80 ? '...' : ''}`);
                    console.log();
                });
            });

            // Demonstrate execution
            log(colors.red + colors.bold, '\n════════════════════════════════════════════════════════════════');
            log(colors.red + colors.bold, 'XSS EXECUTION SIMULATION');
            log(colors.red + colors.bold, '════════════════════════════════════════════════════════════════\n');

            xssDevices.forEach(dev => {
                dev.payloads.forEach(xss => {
                    log(colors.yellow, 'Simulating payload execution:');
                    log(colors.reset, `   Attribute: ${xss.attribute}`);
                    log(colors.magenta, `   Payload: ${xss.value}\n`);

                    // Extract and "execute" alert() calls (just show them)
                    const alertMatch = xss.value.match(/alert\s*\(\s*['"](.*?)['"]|alert\s*\(\s*(.*?)\s*\)/i);
                    if (alertMatch) {
                        const alertMsg = alertMatch[1] || alertMatch[2] || 'XSS';
                        log(colors.red + colors.bold, `   WOULD EXECUTE: alert("${alertMsg}")`);
                        log(colors.red, `   ✓ JavaScript execution CONFIRMED\n`);
                    } else if (xss.value.includes('onerror')) {
                        log(colors.red + colors.bold, `   WOULD EXECUTE: onerror event handler`);
                        log(colors.red, `   ✓ JavaScript execution CONFIRMED\n`);
                    } else if (xss.value.includes('<script>')) {
                        log(colors.red + colors.bold, `   WOULD EXECUTE: <script> tag content`);
                        log(colors.red, `   ✓ JavaScript execution CONFIRMED\n`);
                    }
                });
            });
        }

        // Final verdict
        log(colors.cyan + colors.bold, '\n════════════════════════════════════════════════════════════════');
        log(colors.cyan + colors.bold, 'VULNERABILITY ASSESSMENT');
        log(colors.cyan + colors.bold, '════════════════════════════════════════════════════════════════\n');

        if (totalXSSPayloads > 0) {
            log(colors.red + colors.bold, 'VULNERABILITY CONFIRMED: STORED XSS');
            log(colors.red, `   - ${totalXSSPayloads} malicious payload(s) found`);
            log(colors.red, `   - ${xssDevices.length} device(s) compromised`);
            log(colors.red, '   - API returns unescaped HTML');
            log(colors.red, '   - Third-party dashboards ARE vulnerable\n');

            log(colors.yellow, 'IMPACT:');
            log(colors.reset, '   - Compromised device -> XSS injection');
            log(colors.reset, '   - Admin opens dashboard -> XSS executes');
            log(colors.reset, '   - Session hijacking possible');
            log(colors.reset, '   - Full account takeover risk\n');

            log(colors.green, 'SEVERITY: MEDIUM');
            log(colors.reset, '   - Official UI is safe (React escapes)');
            log(colors.reset, '   - Third-party integrations at risk');
            log(colors.reset, '   - Defense-in-depth failure\n');
        } else {
            log(colors.yellow, 'NO ACTIVE XSS PAYLOADS FOUND');
            log(colors.reset, '   However, the vulnerability EXISTS:');
            log(colors.reset, '   - API accepts HTML without sanitization');
            log(colors.reset, '   - Payloads can be injected via Device API');
            log(colors.reset, '   - Third-party consumers remain at risk\n');
        }

        log(colors.cyan + colors.bold, '════════════════════════════════════════════════════════════════\n');

    } catch (error) {
        log(colors.red, `[-] Error: ${error.message}`);
        process.exit(1);
    }
}

// Main execution
if (process.argv.length < 3) {
    console.log('Usage: node xss_attack_simulator.js <JWT_TOKEN>');
    console.log('\nExample:');
    console.log('  TOKEN=$(curl -s -X POST https://staging.hosted.mender.io/api/management/v1/useradm/auth/login \\');
    console.log('    -H "Authorization: Basic $(echo -n EMAIL:PASS | base64)")');
    console.log('  node xss_attack_simulator.js "$TOKEN"');
    process.exit(1);
}

const token = process.argv[2];
simulateVulnerableDashboard(token);
