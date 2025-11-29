document.addEventListener('DOMContentLoaded', () => {
    // --- QUERY SELECTORS ---
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');
    const fileForm = document.getElementById('file-form');
    const pasteForm = document.getElementById('paste-form');
    const resultsContainer = document.getElementById('results-container');
    const reportDiv = document.getElementById('report');

    // --- EVENT LISTENERS ---

    // Logic to switch between "Upload" and "Paste" tabs
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            tabButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');

            tabContents.forEach(content => content.classList.remove('active'));
            const tabId = button.getAttribute('data-tab');
            document.getElementById(tabId + '-form').classList.add('active');
        });
    });

    // Handler for the File Upload Form
    fileForm.addEventListener('submit', async (event) => {
        event.preventDefault(); // Stop page from reloading
        const fileInput = document.getElementById('email-file-input');
        const file = fileInput.files[0];
        if (!file) return alert('Please select a file.');

        const formData = new FormData();
        formData.append('emailFile', file); // 'emailFile' must match @RequestParam in Java

        await performAnalysis('/api/v1/analyze/email', {
            method: 'POST',
            body: formData,
        });
    });

    // Handler for the Paste Text Form
    pasteForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const contentInput = document.getElementById('email-content-input');
        const content = contentInput.value;
        if (!content.trim()) return alert('Please paste email content.');

        await performAnalysis('/api/v1/analyze/email-content', {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: content,
        });
    });

    // --- CORE FUNCTIONS ---

    // Reusable function to call the backend and display results
    async function performAnalysis(endpoint, options) {
        resultsContainer.classList.remove('hidden');
        reportDiv.innerHTML = '<p>Analyzing, please wait...</p>';
        try {
            const response = await fetch(endpoint, options);
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Server responded with status ${response.status}: ${errorText}`);
            }
            const result = await response.json();
            displayResults(result);
        } catch (error) {
            console.error('Analysis failed:', error);
            reportDiv.innerHTML = `<div class="report-item"><span class="report-key">Error:</span> <span class="report-value suspicious">${error.message}</span></div>`;
        }
    }

    // Function to render the JSON results into user-friendly HTML
    function displayResults(result) {
        reportDiv.innerHTML = ''; // Clear previous results
        const isSuspicious = result.suspicious;
        const verdictClass = isSuspicious ? 'suspicious' : 'safe';

        // Build the HTML to display the report
        let reportHTML = '';
        reportHTML += `<div class="report-item"><span class="report-key">Verdict:</span> <span class="report-value ${verdictClass}">${isSuspicious ? 'SUSPICIOUS' : 'Looks Safe'}</span></div>`;
        reportHTML += `<div class="report-item"><span class="report-key">Summary:</span> ${result.analysisSummary || 'No summary available.'}</div>`;
        reportHTML += `<div class="report-item"><span class="report-key">Claimed Sender:</span> ${result.fromHeader || 'Not found'}</div>`;
        reportHTML += `<div class="report-item"><span class="report-key">Email Origin:</span> ${result.returnPathHeader || 'Not found'}</div>`;

        if (result.foundUrls && result.foundUrls.length > 0) {
            const urlList = result.foundUrls.map(url => `<li>${url}</li>`).join('');
            reportHTML += `<div class="report-item"><span class="report-key">Links Found in Email (${result.foundUrls.length}):</span><ul>${urlList}</ul></div>`;
        } else {
            reportHTML += `<div class="report-item"><span class="report-key">Links Found in Email:</span> None</div>`;
        }

        reportDiv.innerHTML = reportHTML;
    }
});