// background.js

// Initialize storage for issues
chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.set({ issues: {} });
    console.log("Cookie Security Inspector Installed");
});

// Helper to analyze a single cookie
function analyzeCookie(cookie, url) {
    const issues = [];
    const domain = cookie.domain;
    const name = cookie.name;

    // 1. Missing HttpOnly
    if (!cookie.httpOnly) {
        issues.push({
            type: "Missing HttpOnly",
            severity: "High",
            description: `Cookie '${name}' is accessible via JavaScript. This increases XSS risk.`,
            remediation: "Set the 'HttpOnly' flag when setting the cookie."
        });
    }

    // 2. Missing Secure
    if (!cookie.secure) {
        issues.push({
            type: "Missing Secure",
            severity: "High",
            description: `Cookie '${name}' is sent over unencrypted HTTP.`,
            remediation: "Set the 'Secure' flag to ensure it's only sent over HTTPS."
        });
    }

    // 3. SameSite Analysis
    if (!cookie.sameSite || cookie.sameSite === "no_restriction" || cookie.sameSite === "None") {
        if (!cookie.secure) {
            issues.push({
                type: "SameSite=None without Secure",
                severity: "Critical",
                description: `Cookie '${name}' allows cross-site usage but isn't Secure. modern browsers checks this but it's bad practice.`,
                remediation: "If SameSite is 'None', the 'Secure' flag MUST be set."
            });
        }
    }

    // 4. Long-lived cookies (e.g., > 30 days)
    if (cookie.expirationDate) {
        const daysUntilExpiry = (cookie.expirationDate * 1000 - Date.now()) / (1000 * 60 * 60 * 24);
        if (daysUntilExpiry > 30) {
            issues.push({
                type: "Long-lived Cookie",
                severity: "Medium",
                description: `Cookie '${name}' persists for ${Math.round(daysUntilExpiry)} days.`,
                remediation: "Reduce cookie lifetime to minimize session hijacking windows."
            });
        }
    }

    return issues;
}

// Store issues in chrome.storage
function storeIssues(url, newIssues) {
    if (newIssues.length === 0) return;

    chrome.storage.local.get(['issues'], (result) => {
        let allIssues = result.issues || {};
        // Group by domain (simplified for now, using host) 
        // We really want to key by URL or Domain. Let's key by Tab ID or URL for the popup to read easily.
        // For this MVP, let's key by the URL origin or host to show in popup when on that site.

        try {
            const origin = new URL(url).origin;
            if (!allIssues[origin]) {
                allIssues[origin] = [];
            }

            // Deduplicate based on cookie name + issue type
            newIssues.forEach(issue => {
                const exists = allIssues[origin].some(existing =>
                    existing.cookieName === issue.cookieName && existing.type === issue.type
                );
                if (!exists) {
                    allIssues[origin].push(issue);
                }
            });

            chrome.storage.local.set({ issues: allIssues });
        } catch (e) {
            console.error("Invalid URL", url);
        }
    });
}

// 1. Monitor Cookie changes via chrome.cookies API
chrome.cookies.onChanged.addListener((changeInfo) => {
    if (changeInfo.removed) return;

    const cookie = changeInfo.cookie;
    // We need the URL to store it effectively. cookie.domain starts with . often
    // We'll construct a mock URL or try to find active tabs matching domain.
    // For simplicity in this event, let's just analyze.

    const issues = analyzeCookie(cookie);
    if (issues.length > 0) {
        // We need to associate this with a URL.
        const protocol = cookie.secure ? "https:" : "http:";
        const domain = cookie.domain.startsWith('.') ? cookie.domain.substring(1) : cookie.domain;
        const url = `${protocol}//${domain}${cookie.path}`;

        // Enrich issues with cookie name for storage
        const enrichedIssues = issues.map(i => ({ ...i, cookieName: cookie.name }));
        storeIssues(url, enrichedIssues);
    }
});


// 2. WebRequest for Set-Cookie headers
chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        if (details.responseHeaders) {
            details.responseHeaders.forEach((header) => {
                if (header.name.toLowerCase() === 'set-cookie') {
                    // Basic extraction: name is usually the first part before '='
                    const parts = header.value.split(';');
                    const nameVal = parts[0].split('=');
                    if (nameVal.length > 0) {
                        const name = nameVal[0].trim();
                        const lowerValue = header.value.toLowerCase();
                        const issues = [];

                        if (!lowerValue.includes('httponly')) {
                            issues.push({
                                type: "Missing HttpOnly (Header)",
                                severity: "High",
                                description: `Cookie '${name}' in Set-Cookie header lacks HttpOnly flag.`,
                                remediation: "Add '; HttpOnly' to the Set-Cookie header."
                            });
                        }
                        if (!lowerValue.includes('secure')) {
                            issues.push({
                                type: "Missing Secure (Header)",
                                severity: "High",
                                description: `Cookie '${name}' in Set-Cookie header lacks Secure flag.`,
                                remediation: "Add '; Secure' to the Set-Cookie header."
                            });
                        }

                        if (issues.length > 0) {
                            const enrichedIssues = issues.map(i => ({ ...i, cookieName: name }));
                            storeIssues(details.url, enrichedIssues);
                        }
                    }
                }
            });
        }
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders", "extraHeaders"]
);

// 3. Monitor URL parameters for potential session tokens
chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        const url = new URL(details.url);
        const params = url.searchParams;
        const suspiciousKeys = ['session', 'token', 'auth', 'sid', 'jwt', 'bearer'];

        suspiciousKeys.forEach(key => {
            params.forEach((value, paramKey) => {
                if (paramKey.toLowerCase().includes(key)) {
                    // Simple heuristic: if value is longish and looks random
                    if (value.length > 20) {
                        const issue = [{
                            type: "Session Token in URL",
                            severity: "Critical",
                            description: `Possible session token found in URL parameter '${paramKey}'. URLs are logged/cached, exposing this token.`,
                            remediation: "Move session tokens to HTTP headers (Authorization) or secure cookies.",
                            cookieName: "N/A (URL Param)"
                        }];
                        storeIssues(details.url, issue);
                    }
                }
            });
        });
    },
    { urls: ["<all_urls>"] }
);

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getIssues") {
        const url = request.url;
        chrome.storage.local.get(['issues'], (result) => {
            const origin = new URL(url).origin;
            sendResponse({ issues: result.issues[origin] || [] });
        });
        return true; // async response
    }
    if (request.action === "clearIssues") {
        const url = request.url;
        chrome.storage.local.get(['issues'], (result) => {
            const origin = new URL(url).origin;
            const allIssues = result.issues;
            delete allIssues[origin];
            chrome.storage.local.set({ issues: allIssues }, () => {
                sendResponse({ status: "cleared" });
            });
        });
        return true;
    }
});
