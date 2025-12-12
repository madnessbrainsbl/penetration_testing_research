// JavaScript to run in browser console to find cart modification endpoints
// Open browser DevTools → Console → paste this code

console.log("[*] Finding cart modification endpoints...");

// First, get current cart
fetch('https://www.zooplus.de/checkout/api/cart-api/v2/cart/6bd223b4-5040-4faa-ba85-6a85c1ec2d50', {
    credentials: 'include'
})
.then(r => r.json())
.then(cart => {
    console.log("[+] Current cart:", cart);
    const articleId = cart.articles[0].id;
    const offerId = cart.articles[0].offerId;
    
    console.log(`[*] Testing with articleId: ${articleId}, offerId: ${offerId}`);
    
    // Try different endpoints
    const tests = [
        // Try PUT with quantity
        {
            url: `https://www.zooplus.de/checkout/api/cart-api/v2/cart/6bd223b4-5040-4faa-ba85-6a85c1ec2d50/articles/${articleId}`,
            method: 'PUT',
            body: {quantity: 0}
        },
        // Try PATCH
        {
            url: `https://www.zooplus.de/checkout/api/cart-api/v2/cart/6bd223b4-5040-4faa-ba85-6a85c1ec2d50/articles/${articleId}`,
            method: 'PATCH',
            body: {quantity: 0}
        },
        // Try POST with different structure
        {
            url: `https://www.zooplus.de/checkout/api/cart-api/v2/cart/6bd223b4-5040-4faa-ba85-6a85c1ec2d50/articles`,
            method: 'POST',
            body: {articles: [{id: articleId, quantity: 0}]}
        },
        // Try with offerId
        {
            url: `https://www.zooplus.de/checkout/api/cart-api/v2/cart/6bd223b4-5040-4faa-ba85-6a85c1ec2d50/articles`,
            method: 'POST',
            body: {articles: [{offerId: offerId, quantity: 0}]}
        },
        // Try DELETE
        {
            url: `https://www.zooplus.de/checkout/api/cart-api/v2/cart/6bd223b4-5040-4faa-ba85-6a85c1ec2d50/articles/${articleId}`,
            method: 'DELETE'
        }
    ];
    
    tests.forEach((test, i) => {
        setTimeout(() => {
            console.log(`[*] Test ${i+1}: ${test.method} ${test.url}`);
            fetch(test.url, {
                method: test.method,
                headers: {'Content-Type': 'application/json'},
                credentials: 'include',
                body: test.body ? JSON.stringify(test.body) : undefined
            })
            .then(r => {
                console.log(`    HTTP ${r.status}`);
                return r.text().then(text => {
                    if (r.status === 200 || r.status === 204) {
                        console.log(`    [!!!] SUCCESS! Response: ${text.substring(0, 200)}`);
                    } else if (r.status !== 404) {
                        console.log(`    Response: ${text.substring(0, 200)}`);
                    }
                });
            })
            .catch(e => console.log(`    Error: ${e}`));
        }, i * 500);
    });
});

