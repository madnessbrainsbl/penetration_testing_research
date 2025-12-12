// JavaScript для перехвата запросов set-article-quantity
// Выполните в консоли браузера

console.log("[*] Setting up request interceptor...");

// Перехватываем fetch запросы
const originalFetch = window.fetch;
window.fetch = function(...args) {
  const url = args[0];
  if (typeof url === 'string' && url.includes('set-article-quantity')) {
    console.log("\n[!!!] INTERCEPTED REQUEST:");
    console.log("[!!!] URL:", url);
    console.log("[!!!] Method:", args[1]?.method || "GET");
    console.log("[!!!] Headers:", JSON.stringify(args[1]?.headers || {}, null, 2));
    if (args[1]?.body) {
      try {
        const body = typeof args[1].body === 'string' ? JSON.parse(args[1].body) : args[1].body;
        console.log("[!!!] Payload:", JSON.stringify(body, null, 2));
      } catch (e) {
        console.log("[!!!] Payload (raw):", args[1].body);
      }
    }
  }
  return originalFetch.apply(this, args);
};

// Перехватываем XMLHttpRequest
const originalXHROpen = XMLHttpRequest.prototype.open;
const originalXHRSend = XMLHttpRequest.prototype.send;

XMLHttpRequest.prototype.open = function(method, url, ...rest) {
  this._method = method;
  this._url = url;
  return originalXHROpen.apply(this, [method, url, ...rest]);
};

XMLHttpRequest.prototype.send = function(body) {
  if (this._url && this._url.includes('set-article-quantity')) {
    console.log("\n[!!!] INTERCEPTED XHR REQUEST:");
    console.log("[!!!] URL:", this._url);
    console.log("[!!!] Method:", this._method);
    if (body) {
      try {
        const parsed = typeof body === 'string' ? JSON.parse(body) : body;
        console.log("[!!!] Payload:", JSON.stringify(parsed, null, 2));
      } catch (e) {
        console.log("[!!!] Payload (raw):", body);
      }
    }
  }
  return originalXHRSend.apply(this, [body]);
};

console.log("[+] Interceptor ready! Now change quantity in your cart and watch the console.");

