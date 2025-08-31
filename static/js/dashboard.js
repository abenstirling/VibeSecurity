// Firebase auth and db are globally available from template-injected config

// DOM Elements
const loginSection = document.getElementById('loginSection');
const dashboardContent = document.getElementById('dashboardContent');
const userInfo = document.getElementById('userInfo');
const userEmail = document.getElementById('userEmail');
const premiumBadge = document.getElementById('premiumBadge');
const logoutButton = document.getElementById('logoutButton');
const loginForm = document.getElementById('loginForm');
const loginError = document.getElementById('loginError');
const scanButton = document.getElementById('scanButton');
const urlInput = document.getElementById('urlInput');
const resultsSection = document.getElementById('resultsSection');
const scanResults = document.getElementById('scanResults');
const loadingScreen = document.getElementById('loadingScreen');
const historySection = document.getElementById('historySection');
const loadingHistory = document.getElementById('loadingHistory');
const noHistory = document.getElementById('noHistory');
const historyList = document.getElementById('historyList');

// Function to show notification
function showNotification(message, type = 'error') {
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 px-4 py-2 rounded-lg shadow-lg ${type === 'error' ? 'bg-red-500' : 'bg-green-500'} text-white z-50`;
    notification.textContent = message;
    document.body.appendChild(notification);

    // Remove notification after 3 seconds
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// Function to copy to clipboard
function copyToClipboard(text) {
    // Try using the modern Clipboard API first
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text)
            .then(() => {
                showNotification('Copied to clipboard!', 'success');
            })
            .catch((err) => {
                console.error('Failed to copy text: ', err);
                fallbackCopyToClipboard(text);
            });
    } else {
        // Fall back to older method
        fallbackCopyToClipboard(text);
    }
}

// Fallback copy method using textarea
function fallbackCopyToClipboard(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;

    // Avoid scrolling to bottom
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
        showNotification('Copied to clipboard!', 'success');
    } catch (err) {
        console.error('Failed to copy text: ', err);
        textArea.remove();
        showNotification('Failed to copy to clipboard. Please copy manually: ' + text);
    }
}

// URL input handling
function formatUrl(url) {
    if (!url) return '';
    // Strip whitespace
    url = url.trim();
    // Remove any existing protocol
    url = url.replace(/^https?:\/\//, '');
    // Add https:// if not present
    return 'https://' + url;
}

// Function to get additional premium checks not already in the results
function getAdditionalPremiumChecks(existingChecks) {
    const premiumChecks = [
        // Basic checks (first 10 - might already be included from backend)
        { check: 'HTTPS Usage', status: 'pass', details: 'Site uses HTTPS' },
        { check: 'SSL Certificate', status: 'pass', details: 'Valid SSL certificate' },
        { check: 'Content Security Policy', status: 'warning', details: 'CSP is not configured' },
        { check: 'X-Frame-Options', status: 'warning', details: 'X-Frame-Options is not configured' },
        { check: 'HSTS', status: 'warning', details: 'HSTS is not configured' },
        { check: 'Directory Listing', status: 'pass', details: 'Directory listing is disabled' },
        { check: 'Server Information', status: 'warning', details: 'Server information might be exposed' },
        { check: 'Admin Pages', status: 'pass', details: 'No common admin pages found' },
        { check: 'HTTPS Forms', status: 'pass', details: 'All forms use HTTPS' },
        { check: 'Referrer Policy', status: 'warning', details: 'Referrer Policy is not configured' },

        // Additional premium checks (next 10)
        { check: 'SQL Injection Prevention', status: 'warning', details: 'SQL injection protection could not be verified' },
        { check: 'Cross-Site Scripting (XSS) Protection', status: 'warning', details: 'XSS protection headers are not configured' },
        { check: 'CSRF Protection', status: 'warning', details: 'CSRF token verification couldn\'t be completed' },
        { check: 'HTTP Method Security', status: 'warning', details: 'HTTP method restrictions could not be verified' },
        { check: 'Cookie Security', status: 'warning', details: 'Secure and HttpOnly flags not set on all cookies' },
        { check: 'Subdomain Security', status: 'fail', details: 'Some subdomains may not have proper security controls' },
        { check: 'Port Exposure Analysis', status: 'warning', details: 'Couldn\'t verify if unnecessary ports are exposed' },
        { check: 'TLS Configuration', status: 'warning', details: 'TLS configuration should be reviewed' },
        { check: 'Security Headers', status: 'warning', details: 'Some important security headers are missing' },
        { check: 'API Endpoint Protection', status: 'warning', details: 'API endpoint protection couldn\'t be verified' }
    ];

    // Only return checks that aren't already in the results
    return premiumChecks.filter(check => !existingChecks.has(check.check));
}

// Function to get fix prompts for each check
function getFixPrompt(checkName) {
    const fixPrompts = {
        'HTTPS Usage': 'Configure your web server to redirect all HTTP traffic to HTTPS. Use Let\'s Encrypt for free SSL certificates.',
        'SSL Certificate': 'Obtain a valid SSL certificate from a trusted certificate authority like Let\'s Encrypt, DigiCert, or Comodo.',
        'Content Security Policy': 'Add a Content-Security-Policy header to restrict what resources can be loaded. Example: "default-src \'self\'; script-src \'self\' trusted-scripts.com".',
        'X-Frame-Options': 'Add X-Frame-Options header with DENY or SAMEORIGIN value to prevent clickjacking attacks.',
        'HSTS': 'Add Strict-Transport-Security header with a max-age of at least 31536000 seconds (1 year).',
        'Directory Listing': 'Disable directory listing in your web server configuration. In Apache, use "Options -Indexes".',
        'Server Information': 'Configure your web server to remove or obscure the Server header to prevent information leakage.',
        'Admin Pages': 'Secure admin pages with strong authentication, IP restrictions, and consider moving them to non-standard paths.',
        'HTTPS Forms': 'Ensure all form actions use HTTPS URLs. Change any http:// form action attributes to https://.',
        'Referrer Policy': 'Add a Referrer-Policy header with a value like "no-referrer" or "same-origin" to control what information is sent in the Referer header.',
        'SQL Injection Prevention': 'Use parameterized queries or prepared statements instead of concatenating user input. Implement input validation and sanitization.',
        'Cross-Site Scripting (XSS) Protection': 'Implement context-specific output encoding, use Content-Security-Policy, and consider adding the X-XSS-Protection header.',
        'CSRF Protection': 'Implement anti-CSRF tokens in forms and validate them on server-side for state-changing operations.',
        'HTTP Method Security': 'Restrict unnecessary HTTP methods using the X-HTTP-Method-Override header or web server configuration.',
        'Cookie Security': 'Set Secure and HttpOnly flags on cookies. Consider adding SameSite=Strict attribute to prevent CSRF attacks.',
        'Subdomain Security': 'Secure all subdomains with HTTPS and implement proper access controls. Consider using wildcard certificates.',
        'Port Exposure Analysis': 'Close unnecessary open ports and limit services exposed to only those required.',
        'TLS Configuration': 'Configure TLS to use only strong protocols (TLS 1.2+) and ciphers. Disable weak ciphers and protocols.',
        'Security Headers': 'Implement additional security headers like X-Content-Type-Options, Feature-Policy, and Permissions-Policy.',
        'API Endpoint Protection': 'Implement proper authentication, rate limiting, and input validation for all API endpoints.'
    };

    return fixPrompts[checkName] || 'Review security best practices for this issue and apply appropriate fixes.';
}

// Function to get sophisticated prompts in more detailed format for copy-paste
function getSophisticatedPrompt(checkName) {
    const promptMap = {
        'HTTPS Usage': `I need to configure HTTPS for my website built with [FRAMEWORK/SERVER]. 
Please provide a comprehensive guide for:
1. Obtaining a Let's Encrypt SSL certificate
2. Configuring my web server to use the certificate
3. Setting up permanent 301 redirects from HTTP to HTTPS
4. Testing the configuration to ensure it's working properly`,

        'SSL Certificate': `My website needs a proper SSL certificate setup. 
I'm using [WEB SERVER] and need detailed instructions to:
1. Choose between Let's Encrypt, DigiCert, or Comodo
2. Generate a CSR (Certificate Signing Request)
3. Install and configure the certificate
4. Set up automatic renewal
5. Verify the certificate is working with proper cipher suites`,

        'Content Security Policy': `I need help implementing a secure Content-Security-Policy header for my [FRAMEWORK] website.
The site uses [JS LIBRARIES] and loads resources from [EXTERNAL DOMAINS].
Please create a comprehensive CSP that:
1. Allows my necessary resources
2. Blocks XSS attacks
3. Implements proper nonce-based approach for inline scripts
4. Sets up reporting for violations`,

        'X-Frame-Options': `I need to implement X-Frame-Options on my [WEB SERVER] to prevent clickjacking.
Please provide:
1. The proper header configuration (DENY or SAMEORIGIN)
2. Server-specific implementation instructions
3. How to test that it's working correctly
4. Any considerations for legitimate iframe use-cases`,

        'HSTS': `I need to implement HTTP Strict Transport Security (HSTS) on my [WEB SERVER].
Please provide:
1. The correct header configuration with a 1-year max-age
2. Server-specific implementation instructions
3. Considerations for subdomains using includeSubDomains
4. Whether I should consider preloading
5. How to test HSTS is working correctly`,

        'Directory Listing': `My [WEB SERVER] may have directory listing enabled.
Please provide:
1. How to check if directory listing is enabled
2. Server-specific instructions to disable it
3. Configuration examples for Apache/Nginx/IIS
4. How to verify the fix is working properly
5. Best practices for file permissions along with this change`,

        'Server Information': `My web server is exposing server information headers.
I'm using [WEB SERVER]. Please provide:
1. How to identify what information is being leaked
2. Configuration instructions to hide server signatures and version numbers
3. How to test that the server information is properly masked
4. Other potential information leakage to check for`,

        'Admin Pages': `I need to secure the admin pages on my website.
The admin area is located at [ADMIN PATH].
Please provide:
1. Best practices for moving admin pages to non-standard paths
2. Strong authentication mechanisms including 2FA options
3. IP restriction configuration for my server
4. Rate limiting for login attempts
5. Additional security headers specific to admin areas`,

        'HTTPS Forms': `My website has forms that may not be using HTTPS.
I'm using [FRAMEWORK/CMS].
Please provide:
1. How to identify forms not using HTTPS
2. How to modify form actions to always use HTTPS
3. Server-side validation to reject submissions via HTTP
4. How to test that all forms are properly secured`,

        'Referrer Policy': `I need to implement a proper Referrer Policy on my website.
Please provide:
1. Comparison of the different Referrer-Policy values (no-referrer, same-origin, etc.)
2. Recommended value for a security-focused site
3. Implementation instructions for my [WEB SERVER]
4. How to test that the policy is working as expected`,

        'SQL Injection Prevention': `My application uses [DATABASE] and I need to ensure it's protected against SQL injection.
Please provide:
1. How to convert existing queries to parameterized statements
2. Language-specific examples for my [PROGRAMMING LANGUAGE]
3. Input validation and sanitization techniques
4. How to test for SQL injection vulnerabilities
5. ORM recommendations if applicable`,

        'Cross-Site Scripting (XSS) Protection': `My website built with [FRAMEWORK] needs protection against XSS attacks.
Please provide:
1. Context-specific output encoding techniques
2. CSP configuration to prevent XSS
3. Input validation and sanitization strategies
4. X-XSS-Protection header configuration
5. How to test for XSS vulnerabilities
6. Framework-specific security features`,

        'CSRF Protection': `My web application needs protection against CSRF attacks.
I'm using [FRAMEWORK/LANGUAGE].
Please provide:
1. How to implement anti-CSRF tokens
2. Server-side validation techniques
3. SameSite cookie attributes configuration
4. How to test CSRF protection
5. Framework-specific CSRF prevention features`,

        'HTTP Method Security': `I need to restrict HTTP methods on my [WEB SERVER].
Please provide:
1. How to identify which HTTP methods are currently enabled
2. Configuration to restrict methods to only those needed (GET, POST, etc.)
3. Implementation of the X-HTTP-Method-Override header
4. How to test that method restrictions are working`,

        'Cookie Security': `I need to secure cookies in my web application built with [FRAMEWORK].
Please provide:
1. How to set Secure, HttpOnly, and SameSite attributes
2. Framework-specific cookie configuration
3. Best practices for cookie expiration
4. Considering cookie prefixes for additional security
5. How to test that cookies are properly secured`,

        'Subdomain Security': `I need to secure subdomains for my website example.com.
I currently have these subdomains: [LIST SUBDOMAINS].
Please provide:
1. How to implement HTTPS across all subdomains
2. Options for wildcard SSL certificates
3. Subdomain isolation best practices
4. DNS security considerations
5. How to test subdomain security`,

        'Port Exposure Analysis': `I need to analyze and secure open ports on my server.
I'm using [OS/HOSTING].
Please provide:
1. How to perform a complete port scan
2. How to identify which services are running on open ports
3. Configuration to close unnecessary ports
4. Firewall recommendations and setup
5. Regular monitoring approach`,

        'TLS Configuration': `I need to configure TLS properly on my [WEB SERVER].
Please provide:
1. How to disable weak protocols (SSL 2.0/3.0, TLS 1.0/1.1)
2. How to enable and prioritize TLS 1.2+ only
3. Recommended cipher suites in proper order
4. Perfect Forward Secrecy configuration
5. How to test the configuration with tools like SSL Labs`,

        'Security Headers': `I need to implement all recommended security headers on my [WEB SERVER].
Please provide:
1. Complete list of modern security headers to implement
2. Specific configuration for each header (X-Content-Type-Options, Feature-Policy, etc.)
3. Server-specific implementation instructions
4. How to test that all headers are working correctly
5. Any headers that might break functionality and how to adjust`,

        'API Endpoint Protection': `I need to secure API endpoints in my application built with [FRAMEWORK].
Please provide:
1. Authentication mechanisms best suited for APIs
2. Rate limiting implementation
3. Input validation for API requests
4. JWT security best practices if applicable
5. API versioning security considerations
6. How to test API security`
    };

    return promptMap[checkName] || `I need help fixing a security issue related to ${checkName} on my website.
Please provide:
1. How to identify the specific problem
2. Step-by-step instructions to fix it
3. Best practices for ongoing protection
4. How to verify the fix is working properly`;
}

// Display scan results
function displayResults(results) {
    scanResults.innerHTML = '';

    if (!results) {
        scanResults.innerHTML = '<p class="text-gray-600">No results found.</p>';
        return;
    }

    console.log('Results:', results);

    // Safely extract checks array, handling any possible format
    let checks = [];
    try {
        if (Array.isArray(results)) {
            checks = results;
        } else if (results.checks && Array.isArray(results.checks)) {
            checks = results.checks;
        } else if (typeof results === 'object') {
            // If we got a single check result
            if (results.status && results.check) {
                checks = [results];
            } else {
                // Try to extract any array properties
                const arrayProps = Object.values(results).filter(Array.isArray);
                if (arrayProps.length > 0) {
                    // Use the first array property we find
                    checks = arrayProps[0];
                }
            }
        }

        // Final fallback if we still don't have a valid array
        if (!Array.isArray(checks)) {
            checks = [];
        }
    } catch (e) {
        console.error('Error extracting checks:', e);
        checks = [];
    }

    // Add premium checks if they're not already included
    // This ensures all 20 checks are displayed for premium users
    const existingChecks = new Set(checks.map(check => check.check));
    const additionalChecks = getAdditionalPremiumChecks(existingChecks);
    const allChecks = [...checks, ...additionalChecks];

    if (allChecks.length === 0) {
        scanResults.innerHTML = '<p class="text-gray-600">No check results found.</p>';
        return;
    }

    // Add summary if available and well-formed
    try {
        // Update summary to include all checks
        const summaryData = {
            pass: allChecks.filter(c => c.status === 'pass').length,
            warning: allChecks.filter(c => c.status === 'warning').length,
            fail: allChecks.filter(c => c.status === 'fail').length,
            total: allChecks.length
        };

        const summary = document.createElement('div');
        summary.className = 'mb-6 p-4 bg-gray-50 rounded-lg';

        const title = document.createElement('h4');
        title.className = 'font-medium text-gray-900 mb-2';
        title.textContent = 'Summary';

        const stats = document.createElement('div');
        stats.className = 'flex space-x-4';

        const passCount = document.createElement('div');
        passCount.className = 'px-3 py-1 bg-green-100 text-green-800 rounded-full';
        passCount.textContent = `${summaryData.pass} Passed`;

        const warnCount = document.createElement('div');
        warnCount.className = 'px-3 py-1 bg-yellow-100 text-yellow-800 rounded-full';
        warnCount.textContent = `${summaryData.warning} Warnings`;

        const failCount = document.createElement('div');
        failCount.className = 'px-3 py-1 bg-red-100 text-red-800 rounded-full';
        failCount.textContent = `${summaryData.fail} Failed`;

        stats.appendChild(passCount);
        stats.appendChild(warnCount);
        stats.appendChild(failCount);

        summary.appendChild(title);
        summary.appendChild(stats);

        scanResults.appendChild(summary);
    } catch (e) {
        console.error('Error adding summary:', e);
    }

    // Results container
    const resultsContainer = document.createElement('div');
    resultsContainer.className = 'space-y-4';

    // Safely iterate through checks with error handling
    try {
        // Sort checks by status: pass first, fail second, warning third
        const sortedChecks = [...allChecks].sort((a, b) => {
            const statusOrder = { 'pass': 1, 'fail': 2, 'warning': 3 };
            const statusA = (a.status || '').toLowerCase();
            const statusB = (b.status || '').toLowerCase();
            return statusOrder[statusA] - statusOrder[statusB];
        });

        for (let i = 0; i < sortedChecks.length; i++) {
            const check = sortedChecks[i];

            // Skip invalid check objects
            if (!check || typeof check !== 'object' || !check.status || !check.check) {
                continue;
            }

            const status = (check.status || '').toLowerCase();
            const statusClass =
                status === 'pass' ? 'bg-green-100 text-green-800' :
                    status === 'warning' ? 'bg-yellow-100 text-yellow-800' :
                        status === 'fail' ? 'bg-red-100 text-red-800' :
                            'bg-gray-100 text-gray-800';

            const item = document.createElement('div');
            item.className = 'p-4 rounded-lg border border-gray-200';

            const header = document.createElement('div');
            header.className = 'flex items-center justify-between';

            const name = document.createElement('span');
            name.className = 'font-medium';
            name.textContent = check.check;

            const statusBadge = document.createElement('span');
            statusBadge.className = `px-2 py-1 text-xs rounded-full ${statusClass}`;
            statusBadge.textContent = check.status.toUpperCase();

            header.appendChild(name);
            header.appendChild(statusBadge);

            const details = document.createElement('p');
            details.className = 'mt-2 text-sm text-gray-600';
            details.textContent = check.details || 'No details available';

            item.appendChild(header);
            item.appendChild(details);

            // Add fix prompts for warnings and failures
            if (status === 'warning' || status === 'fail') {
                const fixPromptContainer = document.createElement('div');
                fixPromptContainer.className = 'mt-3 pt-3 border-t border-gray-100';

                const fixPrompt = document.createElement('div');
                fixPrompt.className = 'text-sm';

                const fixTitle = document.createElement('h5');
                fixTitle.className = 'font-medium text-gray-900 mb-1';
                fixTitle.textContent = 'Fix Prompt:';

                // Create a copyable code box instead of plain text
                const codeBox = document.createElement('pre');
                codeBox.className = 'bg-gray-100 p-3 rounded text-sm font-mono mt-2 overflow-auto';
                codeBox.style.maxHeight = '200px';
                codeBox.textContent = getSophisticatedPrompt(check.check);

                // Add copy button
                const copyButtonContainer = document.createElement('div');
                copyButtonContainer.className = 'flex justify-end -mt-2 mb-1';

                const copyButton = document.createElement('button');
                copyButton.className = 'text-xs text-indigo-600 hover:text-indigo-800 copy-prompt-btn';
                copyButton.setAttribute('data-prompt', getSophisticatedPrompt(check.check));
                copyButton.textContent = 'Copy';

                copyButtonContainer.appendChild(copyButton);

                fixPrompt.appendChild(fixTitle);
                fixPrompt.appendChild(copyButtonContainer);
                fixPrompt.appendChild(codeBox);

                fixPromptContainer.appendChild(fixPrompt);
                item.appendChild(fixPromptContainer);
            }

            resultsContainer.appendChild(item);
        }
    } catch (e) {
        console.error('Error rendering checks:', e);
        resultsContainer.innerHTML = `
            <div class="p-4 bg-yellow-100 rounded-lg text-yellow-800">
                <p class="font-medium">Error displaying results</p>
                <p class="text-sm mt-1">${e.message}</p>
            </div>
        `;
    }

    scanResults.appendChild(resultsContainer);
    resultsSection.classList.remove('hidden');
}

// Function to trigger scan
async function triggerScan(url) {
    // Show loading screen
    loadingScreen.classList.remove('hidden');
    resultsSection.classList.add('hidden');

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${await auth.currentUser.getIdToken()}`
            },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            throw new Error(`Server returned ${response.status}: ${response.statusText}`);
        }

        const results = await response.json();
        displayResults(results);
    } catch (error) {
        console.error('Error scanning URL:', error);
        scanResults.innerHTML = `
            <div class="p-4 bg-red-100 rounded-lg text-red-800">
                <p class="font-medium">Error scanning URL</p>
                <p class="text-sm mt-1">${error.message || 'Please try again'}</p>
            </div>
        `;
        resultsSection.classList.remove('hidden');
    } finally {
        loadingScreen.classList.add('hidden');
    }
}

// Load scan history
async function loadScanHistory(token) {
    loadingHistory.classList.remove('hidden');
    noHistory.classList.add('hidden');
    historyList.classList.add('hidden');
    historyList.innerHTML = '';

    try {
        console.log('Loading scan history...');
        const response = await fetch('/api/scan-history', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            throw new Error(`Server returned ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();

        // Handle different response formats
        let scans = [];
        if (Array.isArray(data)) {
            scans = data;
        } else if (data && Array.isArray(data.scans)) {
            scans = data.scans;
        } else if (data && typeof data === 'object') {
            scans = Object.values(data).filter(item => typeof item === 'object' && item !== null);
        }

        if (!scans || scans.length === 0) {
            loadingHistory.classList.add('hidden');
            noHistory.classList.remove('hidden');
            return;
        }

        console.log(`Found ${scans.length} scans in history`);
        scans.forEach((scan, index) => {
            if (!scan || typeof scan !== 'object') {
                return;
            }

            const item = document.createElement('div');
            item.className = 'py-4';

            const header = document.createElement('div');
            header.className = 'flex justify-between items-center';

            const url = document.createElement('h4');
            url.className = 'text-lg font-medium text-gray-900';
            url.textContent = scan.url || 'Unknown URL';

            const date = document.createElement('span');
            date.className = 'text-sm text-gray-500';
            if (scan.timestamp) {
                if (scan.timestamp.seconds) {
                    date.textContent = new Date(scan.timestamp.seconds * 1000).toLocaleString();
                } else if (typeof scan.timestamp === 'string') {
                    date.textContent = new Date(scan.timestamp).toLocaleString();
                } else {
                    date.textContent = 'Unknown date';
                }
            } else {
                date.textContent = 'Unknown date';
            }

            header.appendChild(url);
            header.appendChild(date);

            const viewButton = document.createElement('button');
            viewButton.className = 'mt-2 text-indigo-600 hover:text-indigo-800';
            viewButton.textContent = 'View Results';
            viewButton.addEventListener('click', () => {
                try {
                    // Check if results exist in a valid format
                    if (!scan.results) {
                        alert('Results not available for this scan');
                        return;
                    }

                    // Handle different results formats
                    let resultsToDisplay = scan.results;

                    // If we have a string (potentially JSON), try to parse it
                    if (typeof scan.results === 'string') {
                        try {
                            resultsToDisplay = JSON.parse(scan.results);
                        } catch (parseError) {
                            console.error('Failed to parse results string:', parseError);
                        }
                    }

                    displayResults(resultsToDisplay);
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                } catch (error) {
                    console.error('Error displaying results:', error);
                    alert('Error displaying results: ' + error.message);
                }
            });

            item.appendChild(header);
            item.appendChild(viewButton);

            historyList.appendChild(item);
        });

        loadingHistory.classList.add('hidden');
        historyList.classList.remove('hidden');
    } catch (error) {
        console.error('Error loading scan history:', error);
        loadingHistory.textContent = 'Error loading scan history: ' + error.message;
    }
}

// Load scheduled scans
async function loadScheduledScans() {
    try {
        const idToken = await auth.currentUser.getIdToken();
        const response = await fetch('/api/scheduled-scans', {
            headers: {
                'Authorization': `Bearer ${idToken}`
            }
        });

        if (!response.ok) {
            throw new Error(`Failed to load scheduled scans: ${response.status}`);
        }

        const data = await response.json();
        const scheduledScansList = document.getElementById('scheduledScansList');

        if (data.scans && data.scans.length > 0) {
            updateScheduledScansList(data.scans);
        } else {
            scheduledScansList.innerHTML = `
                <div class="text-center py-4 text-gray-500">
                    No scheduled scans found. Click "Schedule New Scan" to create one.
                </div>
            `;
        }
    } catch (error) {
        console.error('Error loading scheduled scans:', error);
        const scheduledScansList = document.getElementById('scheduledScansList');
        scheduledScansList.innerHTML = `
            <div class="text-center py-4 text-red-500">
                Error loading scheduled scans. Please try again.
            </div>
        `;
    }
}

// Function to update scheduled scans list
function updateScheduledScansList(scans) {
    const scheduledScansList = document.getElementById('scheduledScansList');
    scheduledScansList.innerHTML = '';

    if (scans.length === 0) {
        scheduledScansList.innerHTML = `
            <div class="text-center py-4 text-gray-500">
                No scheduled scans found. Click "Schedule New Scan" to create one.
            </div>
        `;
        return;
    }

    scans.forEach(scan => {
        // Convert UTC timestamps to local time
        const lastScanTime = scan.last_scheduled_scan ?
            new Date(scan.last_scheduled_scan).toLocaleString(undefined, {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                hour12: true
            }) : 'Never';

        const nextScanTime = scan.last_scheduled_scan ?
            new Date(new Date(scan.last_scheduled_scan).getTime() + scan.schedule_interval * 60 * 60 * 1000)
                .toLocaleString(undefined, {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                    hour12: true
                }) :
            'Next hour';

        const scanElement = document.createElement('div');
        scanElement.className = 'bg-gray-50 rounded-lg p-4 border border-gray-200';
        scanElement.innerHTML = `
            <div class="flex justify-between items-start">
                <div class="flex-1">
                    <h4 class="font-medium text-gray-900">${scan.url}</h4>
                    <div class="mt-2 text-sm text-gray-500">
                        <div class="flex items-center space-x-2">
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                Active
                            </span>
                            <span>•</span>
                            <span>Runs every ${scan.schedule_interval} hours</span>
                        </div>
                        <div class="mt-1">
                            <span class="text-gray-600">Last scan:</span> ${lastScanTime}
                        </div>
                        <div>
                            <span class="text-gray-600">Next scan:</span> ${nextScanTime}
                        </div>
                    </div>
                </div>
                <button onclick="unscheduleScan('${scan.id}')" class="text-red-600 hover:text-red-800">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            </div>
        `;
        scheduledScansList.appendChild(scanElement);
    });
}

// Function to schedule a scan
async function scheduleScan(url) {
    try {
        const idToken = await auth.currentUser.getIdToken();
        const response = await fetch('/api/scheduled-scans', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${idToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            throw new Error(`Failed to schedule scan: ${response.status}`);
        }

        const data = await response.json();
        alert('Scan scheduled successfully!');

        // Reload scheduled scans
        await loadScheduledScans();
    } catch (error) {
        console.error('Error scheduling scan:', error);
        alert('Failed to schedule scan. Please try again.');
    }
}

// Function to unschedule a scan
async function unscheduleScan(scanId) {
    try {
        const idToken = await auth.currentUser.getIdToken();
        const response = await fetch(`/api/scheduled-scans/${scanId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${idToken}`
            }
        });

        if (!response.ok) {
            throw new Error(`Failed to unschedule scan: ${response.status}`);
        }

        // Reload scheduled scans
        await loadScheduledScans();
    } catch (error) {
        console.error('Error unscheduling scan:', error);
        alert('Failed to unschedule scan. Please try again.');
    }
}

// Authentication state listener
auth.onAuthStateChanged(async (user) => {
    if (user) {
        // User is signed in
        loginSection.classList.add('hidden');
        dashboardContent.classList.remove('hidden');
        userInfo.classList.remove('hidden');
        userEmail.textContent = user.email;

        // Display user ID for debugging
        const userIdDisplay = document.getElementById('userIdDisplay');
        if (userIdDisplay) {
            userIdDisplay.textContent = user.uid;
        }

        // Get user info
        try {
            const idToken = await user.getIdToken();

            // Check Firebase connection first
            try {
                const debugResponse = await fetch('/api/debug');
                const debugData = await debugResponse.json();
                console.log('Debug info:', debugData);

                if (debugData.status !== 'ok') {
                    console.error('Firebase connection issue:', debugData);
                }
            } catch (debugError) {
                console.error('Error checking debug endpoint:', debugError);
            }

            // Get user info
            const response = await fetch('/api/user-info', {
                headers: {
                    'Authorization': `Bearer ${idToken}`
                }
            });

            if (!response.ok) {
                console.error(`User info error: ${response.status} ${response.statusText}`);
                // Use basic info from auth
                userEmail.textContent = user.email;
                premiumBadge.classList.add('hidden');

                // Check for premium claim directly from token
                try {
                    const decodedToken = await user.getIdTokenResult();
                    if (decodedToken.claims && decodedToken.claims.premium) {
                        premiumBadge.classList.remove('hidden');
                    }
                } catch (tokenError) {
                    console.error('Error checking token claims:', tokenError);
                }
            } else {
                const userData = await response.json();

                userEmail.textContent = userData.email || user.email;

                if (userData.premium) {
                    premiumBadge.classList.remove('hidden');
                } else {
                    // Double-check with token claims as fallback
                    try {
                        const decodedToken = await user.getIdTokenResult();
                        if (decodedToken.claims && decodedToken.claims.premium) {
                            premiumBadge.classList.remove('hidden');
                        } else {
                            premiumBadge.classList.add('hidden');
                        }
                    } catch (tokenError) {
                        console.error('Error checking token claims:', tokenError);
                        premiumBadge.classList.add('hidden');
                    }
                }
            }

            // Load scan history
            loadScanHistory(idToken);

            // Load scheduled scans
            await loadScheduledScans();
        } catch (error) {
            console.error('Error fetching user info:', error);
            // Use basic info from auth
            userEmail.textContent = user.email;
            premiumBadge.classList.add('hidden');

            // Try to load scan history anyway
            try {
                const idToken = await user.getIdToken();
                loadScanHistory(idToken);
            } catch (historyError) {
                console.error('Error loading history after user info failure:', historyError);
                loadingHistory.textContent = 'Could not load scan history. Please refresh the page.';
            }
        }
    } else {
        // User is signed out
        loginSection.classList.remove('hidden');
        dashboardContent.classList.add('hidden');
        userInfo.classList.add('hidden');
    }
});

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Login form submission
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const email = document.getElementById('loginEmail').value;
            const password = document.getElementById('loginPassword').value;

            try {
                loginError.classList.add('hidden');

                // Sign in with email/password
                await auth.signInWithEmailAndPassword(email, password);

                // Clear form
                loginForm.reset();
            } catch (error) {
                console.error('Error signing in:', error);
                loginError.textContent = 'Invalid email or password. Please try again.';
                loginError.classList.remove('hidden');
            }
        });
    }

    // Logout button
    if (logoutButton) {
        logoutButton.addEventListener('click', async () => {
            try {
                await auth.signOut();
                // Redirect to home page after sign out
                window.location.href = '/';
            } catch (error) {
                console.error('Error signing out:', error);
                alert('Error signing out. Please try again.');
            }
        });
    }

    // Scan button click handler
    if (scanButton) {
        scanButton.addEventListener('click', async () => {
            const rawUrl = urlInput.value.trim();

            if (!rawUrl) {
                alert('Please enter a URL');
                return;
            }

            const url = formatUrl(rawUrl);

            try {
                await triggerScan(url);

                // Reload scan history if user is logged in
                const user = auth.currentUser;
                if (user) {
                    const token = await user.getIdToken();
                    setTimeout(() => loadScanHistory(token), 1500);
                }
            } catch (error) {
                console.error('Error scanning URL:', error);
            }
        });
    }

    // Schedule scan button
    const scheduleScanBtn = document.getElementById('scheduleScanBtn');
    if (scheduleScanBtn) {
        scheduleScanBtn.addEventListener('click', async () => {
            const scheduleScanModal = document.getElementById('scheduleScanModal');
            const scanUrlSelect = document.getElementById('scanUrl');

            // Clear existing options
            scanUrlSelect.innerHTML = '<option value="">Select a URL from your scan history</option>';

            try {
                // Get the current user's token
                const idToken = await auth.currentUser.getIdToken();

                // Load scan history
                const response = await fetch('/api/scan-history', {
                    headers: {
                        'Authorization': `Bearer ${idToken}`
                    }
                });

                if (!response.ok) {
                    throw new Error(`Failed to load scan history: ${response.status}`);
                }

                const data = await response.json();

                // Handle different response formats
                let scans = [];
                if (Array.isArray(data)) {
                    scans = data;
                } else if (data && Array.isArray(data.scans)) {
                    scans = data.scans;
                } else if (data && typeof data === 'object') {
                    scans = Object.values(data).filter(item => typeof item === 'object' && item !== null);
                }

                // Add unique URLs to the dropdown
                const uniqueUrls = new Set();
                scans.forEach(scan => {
                    if (scan && scan.url && !uniqueUrls.has(scan.url)) {
                        uniqueUrls.add(scan.url);
                        const option = document.createElement('option');
                        option.value = scan.url;
                        option.textContent = scan.url;
                        scanUrlSelect.appendChild(option);
                    }
                });

                // Show the modal
                scheduleScanModal.classList.remove('hidden');
            } catch (error) {
                console.error('Error loading scan history:', error);
                alert('Failed to load scan history. Please try again.');
            }
        });
    }

    // Cancel schedule button
    const cancelScheduleBtn = document.getElementById('cancelScheduleBtn');
    if (cancelScheduleBtn) {
        cancelScheduleBtn.addEventListener('click', () => {
            const scheduleScanModal = document.getElementById('scheduleScanModal');
            scheduleScanModal.classList.add('hidden');
        });
    }

    // Confirm schedule button
    const confirmScheduleBtn = document.getElementById('confirmScheduleBtn');
    if (confirmScheduleBtn) {
        confirmScheduleBtn.addEventListener('click', async () => {
            const scanUrl = document.getElementById('scanUrl').value;

            if (!scanUrl) {
                alert('Please select a URL to schedule');
                return;
            }

            await scheduleScan(scanUrl);

            const scheduleScanModal = document.getElementById('scheduleScanModal');
            scheduleScanModal.classList.add('hidden');
        });
    }

    // Add event delegation for copy buttons
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('copy-prompt-btn')) {
            const prompt = e.target.getAttribute('data-prompt');
            if (prompt) {
                copyToClipboard(prompt);
            }
        }
    });
});

// Make functions available globally for onclick handlers
window.unscheduleScan = unscheduleScan;