document.addEventListener('DOMContentLoaded', () => {
    const issuesList = document.getElementById('issues-list');
    const currentDomainEl = document.getElementById('current-domain');
    const clearBtn = document.getElementById('clear-btn');
    const scanBtn = document.getElementById('scan-btn');

    // Stats elements
    const countCritical = document.getElementById('count-critical');
    const countHigh = document.getElementById('count-high');
    const countMedium = document.getElementById('count-medium');
    const countLow = document.getElementById('count-low');

    // Theme Toggle Logic
    const themeToggleBtn = document.getElementById('theme-toggle');
    const themeIcon = document.getElementById('theme-icon');

    // Moon Icon (for Light Mode -> click to switch to Dark)
    const moonIconSVG = `<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>`;
    // Sun Icon (for Dark Mode -> click to switch to Light)
    const sunIconSVG = `<circle cx="12" cy="12" r="5"></circle>
                    <line x1="12" y1="1" x2="12" y2="3"></line>
                    <line x1="12" y1="21" x2="12" y2="23"></line>
                    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
                    <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
                    <line x1="1" y1="12" x2="3" y2="12"></line>
                    <line x1="21" y1="12" x2="23" y2="12"></line>
                    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
                    <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>`;

    function setTheme(isLight) {
        if (isLight) {
            document.body.classList.add('light-mode');
            themeIcon.innerHTML = moonIconSVG;
            themeIcon.setAttribute('fill', 'currentColor'); // Fill moon
        } else {
            document.body.classList.remove('light-mode');
            themeIcon.innerHTML = sunIconSVG;
            themeIcon.setAttribute('fill', 'none'); // Outline sun
        }
        localStorage.setItem('theme', isLight ? 'light' : 'dark');
    }

    // Load saved preference
    const savedTheme = localStorage.getItem('theme');
    setTheme(savedTheme === 'light');

    themeToggleBtn.addEventListener('click', () => {
        const isLight = document.body.classList.contains('light-mode');
        setTheme(!isLight);
    });

    // Get current tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        const activeTab = tabs[0];
        if (activeTab.url) {
            try {
                const url = new URL(activeTab.url);
                currentDomainEl.textContent = url.hostname;
                showLoading();
                loadIssues(activeTab.url);
            } catch (e) {
                currentDomainEl.textContent = "Invalid URL";
                hideLoading();
            }
        }
    });

    function showLoading() {
        const loadingState = document.getElementById('loading-state');
        if (loadingState) loadingState.classList.remove('hidden');
    }

    function hideLoading() {
        const loadingState = document.getElementById('loading-state');
        if (loadingState) loadingState.classList.add('hidden');
    }

    function loadIssues(url) {
        showLoading();
        // Simulate a brief scan delay for better UX
        setTimeout(() => {
            chrome.runtime.sendMessage({ action: "getIssues", url: url }, (response) => {
                hideLoading();
                renderIssues(response.issues);
            });
        }, 500);
    }

    function renderIssues(issues) {
        issuesList.innerHTML = '';

        let stats = { Critical: 0, High: 0, Medium: 0, Low: 0 };

        if (!issues || issues.length === 0) {
            issuesList.innerHTML = `
                <div class="empty-state">
                    <p>No security issues found on this page!</p>
                </div>`;
            updateStats(stats);
            return;
        }

        issues.forEach(issue => {
            stats[issue.severity]++;

            const card = document.createElement('div');
            card.className = `issue-card ${issue.severity}`;
            card.innerHTML = `
                <div class="issue-header">
                    <span class="issue-title">${issue.type}</span>
                    <span class="cookie-name">${issue.cookieName}</span>
                </div>
                <p class="issue-desc">${issue.description}</p>
                <div class="remediation">
                    <strong>Fix:</strong> ${issue.remediation}
                </div>
            `;
            issuesList.appendChild(card);
        });

        updateStats(stats);
        calculateAndDisplayScore(stats);
    }

    function calculateAndDisplayScore(stats) {
        let score = 100;
        score -= (stats.Critical * 25);
        score -= (stats.High * 15);
        score -= (stats.Medium * 5);
        score -= (stats.Low * 1);

        if (score < 0) score = 0;

        const scoreVal = document.getElementById('score-value');
        const scoreContainer = document.getElementById('score-container');

        scoreVal.textContent = score;
        scoreContainer.classList.remove('hidden');

        // Color code the score
        scoreVal.style.color = score > 80 ? '#51cf66' : (score > 50 ? '#fcc419' : '#ff6b6b');
    }

    function updateStats(stats) {
        countCritical.innerHTML = `${stats.Critical} <small>Critical</small>`;
        countHigh.innerHTML = `${stats.High} <small>High</small>`;
        countMedium.innerHTML = `${stats.Medium} <small>Medium</small>`;
        countLow.innerHTML = `${stats.Low} <small>Low</small>`;
    }

    clearBtn.addEventListener('click', () => {
        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            chrome.runtime.sendMessage({ action: "clearIssues", url: tabs[0].url }, () => {
                loadIssues(tabs[0].url);
            });
        });
    });

    // Manual scan button trigger (re-evaluates all cookies for domain)
    if (scanBtn) {
        scanBtn.addEventListener('click', () => {
            chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
                // To properly "scan" we might want to get all cookies for the domain and re-run analysis
                // Current background listener is passive. Let's add an active scan component later.
                // For now, refreshing the view.
                loadIssues(tabs[0].url);
            });
        });
    }

    // Export Report as PDF
    const exportBtn = document.getElementById('export-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', (e) => {
            e.preventDefault();
            chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
                chrome.runtime.sendMessage({ action: "getIssues", url: tabs[0].url }, (response) => {
                    generatePDF(response.issues, tabs[0].url);
                });
            });
        });
    }

    function generatePDF(issues, url) {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();

        // Get current domain
        let domain = 'Unknown';
        try {
            domain = new URL(url).hostname;
        } catch (e) {
            domain = 'Invalid URL';
        }

        // Calculate stats
        let stats = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        if (issues && issues.length > 0) {
            issues.forEach(issue => {
                stats[issue.severity]++;
            });
        }

        // Title
        doc.setFontSize(18);
        doc.setFont(undefined, 'bold');
        doc.text('Nexure Security Report', 15, 20);

        // Domain
        doc.setFontSize(12);
        doc.setFont(undefined, 'normal');
        doc.text(`Domain: ${domain}`, 15, 30);
        doc.text(`Date: ${new Date().toLocaleString()}`, 15, 37);

        // Summary Stats
        doc.setFontSize(14);
        doc.setFont(undefined, 'bold');
        doc.text('Summary', 15, 50);

        doc.setFontSize(11);
        doc.setFont(undefined, 'normal');
        doc.setTextColor(239, 68, 68); // Critical red
        doc.text(`Critical: ${stats.Critical}`, 15, 58);
        doc.setTextColor(249, 115, 22); // High orange
        doc.text(`High: ${stats.High}`, 15, 65);
        doc.setTextColor(234, 179, 8); // Medium yellow
        doc.text(`Medium: ${stats.Medium}`, 15, 72);
        doc.setTextColor(34, 197, 94); // Low green
        doc.text(`Low: ${stats.Low}`, 15, 79);

        doc.setTextColor(0, 0, 0); // Reset to black

        // Issues List
        let yPos = 95;
        doc.setFontSize(14);
        doc.setFont(undefined, 'bold');
        doc.text('Issues Found', 15, yPos);
        yPos += 10;

        if (!issues || issues.length === 0) {
            doc.setFontSize(11);
            doc.setFont(undefined, 'normal');
            doc.text('No security issues detected!', 15, yPos);
        } else {
            doc.setFontSize(10);
            issues.forEach((issue, index) => {
                // Check if we need a new page
                if (yPos > 270) {
                    doc.addPage();
                    yPos = 20;
                }

                doc.setFont(undefined, 'bold');
                doc.text(`${index + 1}. ${issue.type} [${issue.severity}]`, 15, yPos);
                yPos += 6;

                doc.setFont(undefined, 'normal');
                doc.text(`Cookie: ${issue.cookieName}`, 20, yPos);
                yPos += 6;

                // Description - wrap text
                const descLines = doc.splitTextToSize(issue.description, 170);
                doc.text(descLines, 20, yPos);
                yPos += descLines.length * 5;

                // Remediation - wrap text
                doc.setFont(undefined, 'italic');
                const remLines = doc.splitTextToSize(`Fix: ${issue.remediation}`, 170);
                doc.text(remLines, 20, yPos);
                yPos += remLines.length * 5 + 5;
            });
        }

        // Save the PDF
        doc.save(`Nexure_Security_Report_${domain}_${Date.now()}.pdf`);
    }
});
