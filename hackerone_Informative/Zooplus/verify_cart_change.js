// Проверка изменения корзины Account A
// Выполните в консоли браузера

const CART_UUID = "6bd223b4-5040-4faa-ba85-6a85c1ec2d50";

(async function() {
  console.log("[*] Verifying cart change...");
  
  const cart = await fetch(`https://www.zooplus.de/checkout/api/cart-api/v2/cart/${CART_UUID}`, {
    credentials: 'include'
  }).then(r => r.json());
  
  console.log(`[+] Cart UUID: ${CART_UUID}`);
  console.log(`[+] Cart ID: ${cart.cartId}`);
  console.log(`[+] SID: ${cart.sid}`);
  console.log(`[+] Customer ID: ${cart.customerId || 'N/A'}`);
  console.log(`[+] Articles: ${cart.articles.length}`);
  console.log(`[+] Grand Total: ${cart.summary.grandTotal} EUR`);
  
  console.log("\n[+] Articles details:");
  cart.articles.forEach((article, i) => {
    console.log(`  ${i+1}. ID: ${article.id}, Name: ${article.name}, Quantity: ${article.quantity}, Price: ${article.subTotal} EUR`);
  });
  
  console.log("\n[+] Full cart JSON:");
  console.log(JSON.stringify(cart, null, 2));
})();

