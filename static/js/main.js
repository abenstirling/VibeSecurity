// Get DOM elements
const scanButton = document.getElementById('scanButton');
const urlInput = document.getElementById('urlInput');
const resultsSection = document.getElementById('resultsSection');
const scanResults = document.getElementById('scanResults');
const loadingScreen = document.getElementById('loadingScreen');

// Mobile menu functionality
const mobileMenuButton = document.getElementById('mobile-menu-button');
const mobileMenu = document.getElementById('mobile-menu');

if (mobileMenuButton && mobileMenu) {
    mobileMenuButton.addEventListener('click', () => {
        mobileMenu.classList.toggle('hidden');
    });
}

// Modal functionality
const modalContainer = document.getElementById('modal-container');
const modalTitle = document.getElementById('modal-title');
const modalBody = document.getElementById('modal-body');
const modalClose = document.getElementById('modal-close');

if (modalContainer && modalClose) {
    // Close modal when clicking close button or outside the modal
    modalClose.addEventListener('click', () => {
        modalContainer.classList.add('hidden');
    });

    modalContainer.addEventListener('click', (e) => {
        if (e.target === modalContainer) {
            modalContainer.classList.add('hidden');
        }
    });
}

// Function to show/hide loading screen
function showLoading() {
    if (loadingScreen) {
        loadingScreen.classList.remove('hidden');
    }
}

function hideLoading() {
    if (loadingScreen) {
        loadingScreen.classList.add('hidden');
    }
}

// Function to show notification
function showNotification(message, type = 'error') {
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 px-4 py-2 rounded-lg shadow-lg ${type === 'error' ? 'bg-red-500' : 'bg-green-500'
        } text-white z-50`;
    notification.textContent = message;
    document.body.appendChild(notification);

    // Remove notification after 3 seconds
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// Function to validate URL
function isValidUrl(url) {
    // Check if it's an email
    if (url.includes('@')) {
        return false;
    }

    // Check if it has a domain (contains a dot)
    if (!url.includes('.')) {
        return false;
    }

    // Add https:// if not present
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
    }

    // Basic URL validation
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

// Function to validate URL and update button state
function validateAndUpdateButton() {
    const urlInput = document.getElementById('urlInput');
    const scanButton = document.getElementById('scanButton');
    let url = urlInput.value.trim();

    // Add https:// if not present and URL is otherwise valid
    if (!url.startsWith('http://') && !url.startsWith('https://') && url.includes('.')) {
        urlInput.value = 'https://' + url;
    }

    if (isValidUrl(url)) {
        scanButton.disabled = false;
        urlInput.classList.remove('border-red-500');
        urlInput.classList.add('border-gray-300');
    } else {
        scanButton.disabled = true;
        urlInput.classList.add('border-red-500');
        urlInput.classList.remove('border-gray-300');
    }
}

// Function to copy to clipboard with visual confirmation or fallback notification
function copyToClipboard(text, button) {
    // Try using the modern Clipboard API first
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text)
            .then(() => {
                if (button) {
                    // Visual confirmation
                    const originalContent = button.innerHTML;
                    button.innerHTML = `
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                        </svg>
                        Copied!
                    `;
                    button.classList.remove('text-indigo-600', 'hover:text-indigo-800');
                    button.classList.add('text-green-600');
                    setTimeout(() => {
                        button.innerHTML = originalContent;
                        button.classList.remove('text-green-600');
                        button.classList.add('text-indigo-600', 'hover:text-indigo-800');
                    }, 2000);
                } else {
                    showNotification('Copied to clipboard!', 'success');
                }
            })
            .catch((err) => {
                console.error('Failed to copy text: ', err);
                fallbackCopyToClipboard(text, button);
            });
    } else {
        fallbackCopyToClipboard(text, button);
    }
}

// Fallback copy method using textarea
function fallbackCopyToClipboard(text, button) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.top = '0';
    textArea.style.left = '0';
    textArea.style.position = 'fixed';
    textArea.style.opacity = '0';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
        document.execCommand('copy');
        textArea.remove();
        if (button) {
            const originalContent = button.innerHTML;
            button.innerHTML = `
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                </svg>
                Copied!
            `;
            button.classList.remove('text-indigo-600', 'hover:text-indigo-800');
            button.classList.add('text-green-600');
            setTimeout(() => {
                button.innerHTML = originalContent;
                button.classList.remove('text-green-600');
                button.classList.add('text-indigo-600', 'hover:text-indigo-800');
            }, 2000);
        } else {
            showNotification('Copied to clipboard!', 'success');
        }
    } catch (err) {
        console.error('Failed to copy text: ', err);
        textArea.remove();
        if (button) {
            button.innerHTML = 'Failed to copy';
            button.classList.remove('text-indigo-600', 'hover:text-indigo-800');
            button.classList.add('text-red-600');
            setTimeout(() => {
                button.innerHTML = 'Copy';
                button.classList.remove('text-red-600');
                button.classList.add('text-indigo-600', 'hover:text-indigo-800');
            }, 2000);
        } else {
            showNotification('Failed to copy to clipboard. Please copy manually: ' + text);
        }
    }
}

// Function to create share link
function createShareLink(url) {
    // Get the current URL without query parameters
    const baseUrl = window.location.href.split('?')[0];
    // Create the full share URL with the scanned URL as a parameter
    return `${baseUrl}?url=${encodeURIComponent(url)}`;
}

// Function to get CSRF token from meta tag
function getCsrfToken() {
    const metaTag = document.querySelector('meta[name="csrf-token"]');
    return metaTag ? metaTag.getAttribute('content') : null;
}

// Vulnerability scoring system with better descriptions
const VULNERABILITY_SCORES = {
    'HTTPS Usage': {
        score: 8,
        worstCase: 'Data can be intercepted by attackers, exposing sensitive information',
        passMessage: 'Site uses HTTPS'
    },
    'SSL Certificate': {
        score: 9,
        worstCase: 'Attackers can impersonate the website and steal credentials',
        passMessage: 'SSL certificate is valid and trusted'
    },
    'Content Security Policy': {
        score: 7,
        worstCase: 'Malicious scripts can be injected, leading to data theft',
        passMessage: 'Content Security Policy is properly configured'
    },
    'X-Frame-Options': {
        score: 6,
        worstCase: 'Site can be embedded in malicious pages for clickjacking attacks',
        passMessage: 'X-Frame-Options header prevents clickjacking'
    },
    'HSTS Header': {
        score: 8,
        worstCase: 'Users can be downgraded to HTTP, exposing their data',
        passMessage: 'HSTS header ensures secure connections'
    },
    'Directory Listing': {
        score: 5,
        worstCase: 'Sensitive files and directories can be discovered by attackers',
        passMessage: 'Directory listing is disabled'
    },
    'Server Information': {
        score: 4,
        worstCase: 'Attackers can target specific server vulnerabilities',
        passMessage: 'Server information is properly hidden'
    },
    'Admin Pages': {
        score: 7,
        worstCase: 'Unauthorized access to admin functions can lead to complete compromise',
        passMessage: 'Admin pages are properly secured'
    },
    'HTTPS Forms': {
        score: 8,
        worstCase: 'Form data can be intercepted, exposing user credentials',
        passMessage: 'All forms use HTTPS'
    },
    'Exposed API Keys': {
        score: 9,
        worstCase: 'Attackers can gain unauthorized access to your services and data',
        passMessage: 'No exposed API keys found'
    },
    'API Rate Limiting': {
        score: 7,
        worstCase: 'API endpoints can be abused for DoS attacks',
        passMessage: 'All API endpoints have rate limiting'
    }
};

// Function to calculate security score
function calculateSecurityScore(results) {
    if (!results || !results.checks) return 0;

    const checks = results.checks;
    let totalScore = 0;
    let maxScore = 0;

    checks.forEach(check => {
        const checkName = check.name || check.check || 'Unknown Check';
        const vulnerability = VULNERABILITY_SCORES[checkName] || { score: 5 };
        const status = (check.status || 'unknown').toLowerCase();

        maxScore += vulnerability.score;

        if (status === 'pass' || status === 'passed') {
            totalScore += vulnerability.score;
        } else if (status === 'warn' || status === 'warning') {
            totalScore += vulnerability.score * 0.5; // Half points for warnings
        }
    });

    // Calculate percentage score
    const score = maxScore > 0 ? Math.round((totalScore / maxScore) * 100) : 0;
    return score;
}

// Function to get fix prompts for each check
function getFixPrompt(checkName) {
    const fixPrompts = {
        'HTTPS Usage': 'For Apache: RewriteEngine On; RewriteCond %{HTTPS} off; RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]; For Nginx: server { listen 80; server_name your-domain.com; return 301 https://$server_name$request_uri; }',
        'SSL Certificate': 'Get SSL certificate from Let\'s Encrypt: certbot certonly --webroot -w /var/www/html -d example.com; Install in Apache: SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem; SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem; For Nginx: ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem; ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;',
        'Content Security Policy': 'For Next.js add to next.config.js: module.exports = { async headers() { return [{ source: "/:path*", headers: [{ key: "Content-Security-Policy", value: "default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'unsafe-eval\'; style-src \'self\' \'unsafe-inline\';" }] }]; } }; For FastAPI: @app.middleware("http") async def add_csp(request, call_next): response = await call_next(request); response.headers["Content-Security-Policy"] = "default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'unsafe-eval\'; style-src \'self\' \'unsafe-inline\';"; return response',
        'X-Frame-Options': 'For Apache add to .htaccess: Header set X-Frame-Options "SAMEORIGIN"; For Nginx add to nginx.conf: add_header X-Frame-Options "SAMEORIGIN"; For Next.js add to next.config.js: module.exports = { async headers() { return [{ source: "/:path*", headers: [{ key: "X-Frame-Options", value: "SAMEORIGIN" }] }]; } }',
        'HSTS': 'For Apache add to .htaccess: Header set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"; For Nginx add to nginx.conf: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"; For Next.js add to next.config.js: module.exports = { async headers() { return [{ source: "/:path*", headers: [{ key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains; preload" }] }]; } }',
        'Directory Listing': 'For Apache add to .htaccess: Options -Indexes; For Nginx add to nginx.conf: location / { autoindex off; }; For Express.js: app.use(express.static("public", { dotfiles: "ignore", index: false })); For FastAPI: app.mount("/static", StaticFiles(directory="static", html=False))',
        'Server Information': 'For Next.js, use a custom server to set res.setHeader(\'Server\', \'WebServer\') and remove res.removeHeader(\'X-Powered-By\'), or in Vercel, add a vercel.json with headers: [{ "key": "Server", "value": "WebServer" }]. For FastAPI, add middleware to set response.headers[\'Server\'] = \'WebServer\' and remove response.headers.pop(\'X-Powered-By\', None), or configure Uvicorn with server_header=False.',
        'Admin Pages': 'Restrict access to admin pages: require authentication (e.g., middleware), use strong passwords, limit by IP, and move admin routes to non-standard URLs; Example (Express): app.use(\'/admin\', requireAuth, requireAdmin); Example (Nginx): location /admin { allow 192.168.1.0/24; deny all; }',
        'HTTPS Forms': 'For HTML forms add: <form action="https://example.com/submit" method="POST">; For Next.js add middleware: export function middleware(req) { if (req.method === "POST" && !req.url.startsWith("https://")) { return new Response(null, { status: 308, headers: { Location: req.url.replace("http://", "https://") } }); } }; For Express: app.use((req, res, next) => { if (req.method === "POST" && !req.secure) return res.redirect(308, `https://${req.headers.host}${req.url}`); next(); })',
        'Exposed API Keys': 'Remove API keys from code; store them in environment variables or secret manager; never commit secrets to version control; Example (Node): process.env.API_KEY; Example (Python): os.environ[\'API_KEY\']',
        'API Rate Limiting': 'Implement rate limiting middleware; Example (Express): app.use(rateLimit({ windowMs: 15*60*1000, max: 100 })); Example (Nginx): limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s; limit_req zone=mylimit burst=20;'
    };

    return fixPrompts[checkName] || 'Review security best practices and implement appropriate fixes for this issue';
}

// Function to create result item
function createResultItem(check) {
    const item = document.createElement('div');
    item.className = `p-6 rounded-lg mb-4 ${check.status === 'pass' ? 'bg-green-50 border border-green-100' :
        check.status === 'warning' ? 'bg-yellow-50 border border-yellow-100' :
            'bg-red-50 border border-red-100'
        }`;

    // Status badge
    const statusBadge = document.createElement('div');
    statusBadge.className = `inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium mb-2 ${check.status === 'pass' ? 'bg-green-100 text-green-800' :
        check.status === 'warning' ? 'bg-yellow-100 text-yellow-800' :
            'bg-red-100 text-red-800'
        }`;
    statusBadge.textContent = check.status.toUpperCase();

    // Check name
    const name = document.createElement('h4');
    name.className = 'text-lg font-semibold text-gray-900 mb-1';
    name.textContent = check.check;

    // Check details with checkmark for passed tests
    const details = document.createElement('div');
    details.className = 'flex items-start space-x-2';

    if (check.status === 'pass') {
        const checkmark = document.createElement('span');
        checkmark.className = 'text-green-500 mt-1';
        checkmark.innerHTML = '<svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path></svg>';
        details.appendChild(checkmark);
    }

    const detailsText = document.createElement('p');
    detailsText.className = 'text-sm text-gray-600';
    detailsText.textContent = check.details;
    details.appendChild(detailsText);

    // Append elements
    item.appendChild(statusBadge);
    item.appendChild(name);
    item.appendChild(details);

    // Add fix code if status is not pass
    if (check.status !== 'pass') {
        const fixPromptContainer = document.createElement('div');
        fixPromptContainer.className = 'mt-4 bg-white rounded-lg border border-gray-200';

        // Define codeToShow before using it
        let codeToShow = getFixPrompt(check.check);

        const fixTitle = document.createElement('div');
        fixTitle.className = 'flex justify-between items-center p-3 border-b border-gray-200';

        const fixTitleText = document.createElement('h4');
        fixTitleText.className = 'font-medium text-gray-900';
        fixTitleText.textContent = 'Prompt To Fix:';

        // Only ONE copy button
        const copyButton = document.createElement('button');
        copyButton.className = 'text-sm text-indigo-600 hover:text-indigo-800 copy-prompt-btn flex items-center gap-1';
        copyButton.innerHTML = `
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
            </svg>
            Copy
        `;
        copyButton.setAttribute('data-prompt', codeToShow);

        fixTitle.appendChild(fixTitleText);
        fixTitle.appendChild(copyButton);

        const codeBox = document.createElement('pre');
        codeBox.className = 'p-4 text-sm font-mono overflow-x-auto bg-gray-50';
        codeBox.textContent = codeToShow;

        fixPromptContainer.appendChild(fixTitle);
        fixPromptContainer.appendChild(codeBox);
        item.appendChild(fixPromptContainer);
    }

    return item;
}

// Function to display results
function displayResults(results) {
    const scanResults = document.getElementById('scanResults');
    scanResults.innerHTML = '';

    if (!results || !results.checks) {
        scanResults.innerHTML = '<p class="text-gray-600">No results found.</p>';
        return;
    }

    // Store results for outreach message
    lastScanResults = results;
    lastScanUrl = results.url;

    // Calculate vibe score
    const vibeScore = calculateSecurityScore(results);
    const score = Math.max(0, Math.min(100, vibeScore));
    const scoreColor = score >= 80 ? '#4ade80' : score >= 60 ? '#facc15' : '#ef4444';
    const ringBgColor = score >= 80 ? '#dcfce7' : score >= 60 ? '#fef9c3' : '#fee2e2';
    const textColor = score >= 80 ? 'text-green-500' : score >= 60 ? 'text-yellow-500' : 'text-red-500';
    const progress = (score / 100) * 283; // 2 * PI * r (r=45)

    // Create share link
    const shareLink = createShareLink(results.url);

    // Vibe Score Ring Section
    const vibeScoreDiv = document.createElement('div');
    vibeScoreDiv.className = 'mb-12 text-center';
    vibeScoreDiv.innerHTML = `
        <h3 class="text-3xl font-bold mb-6" style="color: ${scoreColor}">Vibe Score</h3>
        <div class="relative w-56 h-56 mx-auto mb-6">
            <svg class="w-full h-full" viewBox="0 0 100 100">
                <!-- Background circle -->
                <circle cx="50" cy="50" r="45" fill="none" stroke="${ringBgColor}" stroke-width="8" />
                <!-- Score circle (rotated to start at top) -->
                <circle cx="50" cy="50" r="45" fill="none" stroke="${scoreColor}" stroke-width="8" 
                        stroke-dasharray="283" stroke-dashoffset="${283 - progress}" 
                        style="transition: stroke-dashoffset 0.6s;"
                        transform="rotate(-90 50 50)" />
                <!-- Score text, perfectly centered -->
                <text x="50" y="50" text-anchor="middle" dominant-baseline="middle" font-size="38" font-weight="bold" fill="${scoreColor}">${score}</text>
            </svg>
        </div>
        <div class="text-gray-500 text-lg mb-8">out of 100</div>
        <button onclick="copyToClipboard('${shareLink}')" class="px-8 py-4 bg-indigo-600 text-white rounded-xl hover:bg-indigo-700 transition-colors flex items-center gap-2 mx-auto shadow-lg hover:shadow-xl text-lg font-medium">
            <i class="fas fa-share-alt"></i>
            Share Results
        </button>
    `;
    scanResults.appendChild(vibeScoreDiv);

    // Add individual check results (below the score)
    const checksContainer = document.createElement('div');
    checksContainer.className = 'space-y-4';
    results.checks.forEach(check => {
        const item = createResultItem(check);
        checksContainer.appendChild(item);
    });
    scanResults.appendChild(checksContainer);

    document.getElementById('resultsSection').classList.remove('hidden');

    // Scroll to results
    requestAnimationFrame(() => {
        document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
}

// Function to trigger scan
async function triggerScan(url) {
    // Prevent multiple scans
    if (scanButton.disabled) {
        return;
    }

    try {
        // Disable the scan button and show loading state
        scanButton.disabled = true;
        scanButton.innerHTML = `
            <svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white inline-block" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            Scanning...
        `;

        // Show loading
        showLoading();

        // Format URL (ensure it has https://)
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }

        // Call the API
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCsrfToken()
            },
            body: JSON.stringify({
                url: url,
                token: typeof auth !== 'undefined' && auth.currentUser ? await auth.currentUser.getIdToken() : null,
            }),
        });

        if (!response.ok) {
            throw new Error(`Server returned ${response.status}: ${response.statusText}`);
        }

        const results = await response.json();

        // Ensure results is in the correct format
        if (!results || typeof results !== 'object') {
            throw new Error('Invalid response format from server');
        }

        displayResults(results);
    } catch (error) {
        console.error('Error scanning URL:', error);
        scanResults.innerHTML = `
            <div class="p-4 bg-red-100 rounded-lg">
                <p class="text-red-800 font-medium">Error scanning URL</p>
                <p class="text-red-600">${error.message}</p>
            </div>
        `;
        resultsSection.classList.remove('hidden');
        // Also scroll to results on error
        requestAnimationFrame(() => {
            resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
    } finally {
        // Re-enable the scan button and restore its original text
        scanButton.disabled = false;
        scanButton.innerHTML = '<i class="fas fa-search"></i> Scan Now';
        hideLoading();
    }
}

// Secret outreach message feature
let lastScanResults = null;
let lastScanUrl = null;

// Outreach message generator
function generateOutreachMessage(results, url) {
    if (!results || !results.checks) return '';
    const domain = (url || '').replace(/^https?:\/\//, '').replace(/\/$/, '');
    const score = (window.calculateSecurityScore ? window.calculateSecurityScore(results) : 0) || 0;
    const shareLink = window.createShareLink ? window.createShareLink(url) : url;
    // Emoji summary
    const findings = results.checks.map(check => {
        const name = check.name || check.check || '';
        const status = (check.status || '').toLowerCase();
        if (status === 'pass' || status === 'passed') {
            if (name.match(/ssl|https/i)) return '✅ Valid SSL and HTTPS';
            return null; // Don't list all passes
        } else if (status === 'fail' || status === 'failed') {
            if (name.match(/content security policy/i)) return '⚠️ Missing Content Security Policy (CSP)';
            if (name.match(/hsts/i)) return '⚠️ No HTTP Strict Transport Security (HSTS)';
            if (name.match(/directory listing/i)) return '⚠️ Directory listing may be enabled';
            if (name.match(/admin/i)) return '⚠️ Admin page found at /admin';
            if (name.match(/rate limit/i)) return '⚠️ API endpoints without rate limiting';
            if (name.match(/server information/i)) return '⚠️ Server information exposed';
            // Fallback
            return `⚠️ ${name} issue`;
        } else if (status === 'warning' || status === 'warn') {
            return `⚠️ ${name} warning`;
        }
        return null;
    }).filter(Boolean).join('\n');
    return `Hi there,\n\nI'm Ben Stirling, founder of VibeSecurity.co — we scan modern websites for security misconfigurations and deliver clear, actionable fix prompts.\n\nI ran a free scan of ${domain} and wanted to share a few important findings:\n\nYour Vibe Score: ${score} / 100\nScan link: ${shareLink}\n\n${findings}\n\nEach issue includes a copy-pasteable fix prompt tailored to frameworks like Next.js and FastAPI.\n\nWhy it matters:\nSmall misconfigs like these are common, but they can open doors to XSS, clickjacking, credential stuffing, or targeted API abuse. We built Vibe Security to give fast, developer-friendly fixes — perfect for solo devs, agencies, or startup teams.\n\nIf this is something you or your team would want to stay ahead of, we offer ongoing monitoring, PDF reports, Slack/Discord alerts, and full scan histories — all starting at $1.\n\nLet me know if I can help or if you'd like a full breakdown.\n\nStay secure,\nBen Stirling\nFounder, VibeSecurity.co`;
}

// Function to handle URL parameters
function handleUrlParameters() {
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url');

    if (targetUrl) {
        // Set the URL in the input field
        urlInput.value = targetUrl;
        // Validate the URL and enable the scan button if valid
        validateAndUpdateButton();
        // If valid, automatically trigger the scan
        if (isValidUrl(targetUrl)) {
            // Small delay to ensure DOM is ready
            setTimeout(() => {
                triggerScan(targetUrl);
            }, 100);
        }
    }
}

// Add event delegation for copy buttons
document.addEventListener('click', (e) => {
    if (e.target.closest('.copy-prompt-btn')) {
        const button = e.target.closest('.copy-prompt-btn');
        const prompt = button.getAttribute('data-prompt');
        if (prompt) {
            copyToClipboard(prompt, button);
        }
    }
});

// Add CSS for timing summary
const style = document.createElement('style');
style.textContent = `
    .timing-summary-section {
        background-color: #f8f9fa;
        border-radius: 8px;
        padding: 20px;
        margin: 20px 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .timing-stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 15px;
        margin: 15px 0;
    }
    
    .timing-item {
        background-color: white;
        padding: 15px;
        border-radius: 6px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    
    .timing-label {
        display: block;
        font-size: 0.9em;
        color: #666;
        margin-bottom: 5px;
    }
    
    .timing-value {
        font-size: 1.2em;
        font-weight: 600;
        color: #2c3e50;
    }
    
    .slowest-checks {
        margin-top: 20px;
        padding-top: 15px;
        border-top: 1px solid #eee;
    }
    
    .slowest-checks h4 {
        color: #2c3e50;
        margin-bottom: 10px;
    }
    
    .slowest-checks ul {
        list-style: none;
        padding: 0;
        margin: 0;
    }
    
    .slowest-checks li {
        padding: 8px 0;
        border-bottom: 1px solid #eee;
    }
    
    .slowest-checks li:last-child {
        border-bottom: none;
    }
    
    .check-name {
        font-weight: 600;
        color: #2c3e50;
    }
    
    .check-time {
        color: #e74c3c;
        font-weight: 600;
        margin-left: 10px;
    }
    
    .check-details {
        color: #666;
        font-size: 0.9em;
        margin-left: 10px;
    }
`;
document.head.appendChild(style);

// Event listeners for scan functionality
document.addEventListener('DOMContentLoaded', () => {
    // Handle URL parameters
    handleUrlParameters();
    
    // Add event listener for scan button
    if (scanButton) {
        scanButton.addEventListener('click', async () => {
            const url = urlInput.value.trim();
            if (isValidUrl(url)) {
                await triggerScan(url);
            } else {
                showNotification('Please enter a valid URL (e.g., example.com)');
            }
        });
    }

    // Add event listener for Enter key
    if (urlInput) {
        urlInput.addEventListener('input', validateAndUpdateButton);
        urlInput.addEventListener('keypress', async (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                const url = e.target.value.trim();
                if (isValidUrl(url)) {
                    await triggerScan(url);
                } else {
                    showNotification('Please enter a valid URL (e.g., example.com)');
                }
            }
        });
    }
});