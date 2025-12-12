// Перехват следующего PUT запроса set-article-quantity
// Выполните в консоли браузера ПЕРЕД тем как кликнете на кнопку изменения количества

console.log("[*] Setting up interceptor for set-article-quantity...");

const originalFetch = window.fetch;
window.fetch = function(...args) {
  const url = args[0];
  if (typeof url === 'string' && url.includes('set-article-quantity')) {
    console.log("\n[!!!] ========================================");
    console.log("[!!!] INTERCEPTED REQUEST!");
    console.log("[!!!] ========================================");
    console.log("[!!!] URL:", url);
    console.log("[!!!] Method:", args[1]?.method || "GET");
    console.log("[!!!] Headers:", JSON.stringify(args[1]?.headers || {}, null, 2));
    if (args[1]?.body) {
      try {
        const body = typeof args[1].body === 'string' ? JSON.parse(args[1].body) : args[1].body;
        console.log("[!!!] PAYLOAD:", JSON.stringify(body, null, 2));
        window.interceptedPayload = body;
      } catch (e) {
        console.log("[!!!] PAYLOAD (raw):", args[1].body);
        window.interceptedPayload = args[1].body;
      }
    }
    console.log("[!!!] ========================================");
  }
  return originalFetch.apply(this, args);
};

console.log("[+] Interceptor ready! Now click the quantity button and watch the console.");

