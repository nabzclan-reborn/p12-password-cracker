document.addEventListener('DOMContentLoaded', () => {
    // --- Elements ---
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const fileInfo = document.getElementById('file-info');
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');
    const modeOptions = document.querySelectorAll('input[name="attack-mode"]');
    const settingsArea = document.getElementById('settings-area');
    const consoleOutput = document.getElementById('console-output');
    const clearConsoleBtn = document.querySelector('.clear-console');
    const userProfileEl = document.getElementById('user-profile');

    // Change View Elements
    const dropZoneChange = document.getElementById('drop-zone-change');
    const fileInputChange = document.getElementById('file-input-change');
    const fileInfoChange = document.getElementById('file-info-change');
    const oldPassInput = document.getElementById('old-password');
    const newPassInput = document.getElementById('new-password');
    const changeBtn = document.getElementById('change-btn');

    // Tabs
    const tabs = document.querySelectorAll('.nav-btn');
    const views = document.querySelectorAll('.view');

    let selectedFile = null;
    let selectedFileChange = null;
    let eventSource = null;

    // --- Tab Switching ---
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.tab;

            // Views
            views.forEach(v => {
                v.classList.add('hidden');
                v.classList.remove('active');
            });
            const targetView = document.getElementById(`${target}-view`);
            if (targetView) {
                targetView.classList.remove('hidden');
                setTimeout(() => targetView.classList.add('active'), 10);
            }

            // Buttons
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
        });
    });

    // ... (rest of element declarations)

    // --- Stop Logic ---
    stopBtn.addEventListener('click', () => {
        if (eventSource) {
            eventSource.close();
            eventSource = null;
        }
        log('warning', 'Process Cancelled by User.');
        resetBtn();
    });

    // ... (rest of code)

    function handleApiError(error) {
        if (!error) {
            showModal('error', 'Error', 'Unknown error occurred');
            return;
        }

        if (typeof error === 'string') {
            showModal('error', 'Error', error);
            return;
        }

        const code = error.error || 'unknown_error';
        const msg = error.message || 'An error occurred';

        if (code === 'feature_not_available') {
            showModal('error', 'VIP Feature Required ⭐️', msg + '\n\nPlease upgrade to access this feature.');
        } else if (code === 'limit_exceeded') {
            showModal('error', 'Limit Reached ⚠️', msg);
        } else if (code === 'rate_limit_exceeded') {
            showModal('error', 'Rate Limited ⏳', msg);
        } else if (code === 'policy_agreement_required') {
            showModal('error', 'Policy Update 📝', msg, error.agreement_url, true, 'VIEW POLICY');
        } else {
            showModal('error', 'Error ❌', msg);
        }
    }

    // --- Cracking ---
    startBtn.addEventListener('click', async () => {
        if (startBtn.disabled) return;

        // Prevent double requests
        if (startBtn.innerHTML.includes('CRACKING')) return;

        if (!selectedFile) {
            log('error', 'No file selected. Please drop a P12 file first.');
            shake(dropZone);
            return;
        }

        const mode = document.querySelector('input[name="attack-mode"]:checked').value;
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('mode', mode);

        if (mode === 'brute_force') {
            const charset = document.querySelector('input[name="charset"]').value;
            const maxLen = document.querySelector('input[name="max_length"]').value;
            formData.append('charset', charset);
            formData.append('max_length', maxLen);
        } else if (mode === 'dictionary') {
            const wordlistType = document.getElementById('wordlist-type').value;
            console.log('DEBUG: Wordlist Type:', wordlistType);

            if (wordlistType === 'url') {
                const url = document.getElementById('wordlist-url').value;
                if (url) formData.append('wordlist_url', url);
            } else if (wordlistType === 'upload') {
                const fileInput = document.getElementById('wordlist-file');
                console.log('DEBUG: File Input:', fileInput);
                if (fileInput && fileInput.files.length > 0) {
                    const wlFile = fileInput.files[0];
                    console.log('DEBUG: Appending file:', wlFile.name);
                    formData.append('wordlist', wlFile);
                } else {
                    console.log('DEBUG: No wordlist file selected');
                }
            }
        }

        // Initialize Stream
        initLogStream();

        log('system', 'Starting cracking process...');
        startBtn.disabled = true;
        startBtn.style.display = 'none'; // Hide start
        stopBtn.style.display = 'block'; // Show stop
        startBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> CRACKING...';

        try {
            const res = await fetch('/api/crack', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();

            if (!res.ok || (data && !data.success && data.error)) {
                // If status is not OK OR logic says success: false
                const error = data.error || data.message || 'Unknown error';
                log('error', typeof error === 'string' ? error : (error.message || 'Error occurred'));
                handleApiError(error);
                resetBtn();
            }
        } catch (err) {
            log('error', 'Network error: ' + err.message);
            resetBtn();
        }
    });

    // ... (log function)

    function initLogStream() {
        if (eventSource) eventSource.close();

        eventSource = new EventSource('/api/stream');

        eventSource.onmessage = (e) => {
            const data = JSON.parse(e.data);
            if (data.log) {
                // ... (logging logic unchanged)

                // Check for completion events
                const cleanLog = data.log.replace(/\x1b\[[0-9;]*m/g, '');

                if (cleanLog.includes('[+] SUCCESS: Password found:')) {
                    const password = cleanLog.split('Password found:')[1].trim();
                    showModal('success', 'Password Found!', 'The password was successfully Cracked.', password);
                    resetBtn();
                } else if (cleanLog.includes('[-] Failed') && cleanLog.includes('password')) {
                    showModal('error', 'Crack Failed', 'Could not find the password with current settings.');
                    resetBtn();
                } else if (cleanLog.includes('Attempts:') && cleanLog.includes('Time taken:')) {
                    // This often appears at the end of a run, but wait for explicit success/fail message usually
                    // If we see this but no success message yet, and we haven't stopped...
                    // Actually, let's rely on the explicit success/fail logs above.
                }
            }
        };
        // ...
    }

    function resetBtn() {
        if (eventSource) {
            eventSource.close();
            eventSource = null;
        }
        stopBtn.style.display = 'none';
        startBtn.style.display = 'block';
        startBtn.disabled = false;
        startBtn.innerHTML = '<span>START CRACKING</span><i class="fa-solid fa-play"></i>';
    }
    const resultModal = document.getElementById('result-modal');
    const closeModalBtn = document.getElementById('close-modal-btn');
    const modalTitle = document.querySelector('.modal-title');
    const modalMessage = document.querySelector('.modal-message');
    const modalIcon = document.querySelector('.modal-icon i');
    const modalPasswordBox = document.getElementById('modal-password-box');
    const modalPasswordCode = modalPasswordBox.querySelector('code');
    const copyBtn = document.querySelector('.copy-btn');

    // --- User Profile ---
    fetchUserProfile();

    // --- Notifications ---
    if ("Notification" in window) {
        if (Notification.permission !== "granted" && Notification.permission !== "denied") {
            Notification.requestPermission();
        }
    }

    function sendNotification(title, body, type = 'info') {
        if ("Notification" in window && Notification.permission === "granted") {
            new Notification(title, {
                body: body,
                icon: '/static/img/favicon.ico' // fallback if doesn't exist
            });
        }
    }

    // --- Modal Logic ---
    function showModal(type, title, message, dataContent = null, isUrl = false, buttonLabel = 'DOWNLOAD FILE') {
        // Trigger notification
        if (type === 'success') {
            sendNotification('Success! 🔓', message);
        } else if (type === 'error') {
            sendNotification('Failed ❌', message);
        }

        const card = resultModal.querySelector('.modal-card');

        // Reset classes
        card.classList.remove('success', 'error');
        card.classList.add(type);

        // Update content
        modalTitle.textContent = title;
        modalMessage.textContent = message;

        // Icon
        modalIcon.className = type === 'success' ? 'fa-solid fa-check' : 'fa-solid fa-xmark';

        // Content Box (Password or URL)
        const passwordBox = document.getElementById('modal-password-box');
        const codeEl = passwordBox.querySelector('code');
        const copyBtn = document.querySelector('.copy-btn');
        let downloadBtn = document.getElementById('modal-download-btn'); // Need to add this in HTML or create dynamically

        // Reset buttons
        if (copyBtn) copyBtn.style.display = 'none';
        if (downloadBtn) downloadBtn.style.display = 'none';
        passwordBox.classList.add('hidden');

        if (dataContent) {

            if (isUrl) {
                // It's a URL - hide the text box
                passwordBox.classList.add('hidden');

                // Create or show download button
                let btn = document.getElementById('modal-download-btn');
                if (!btn) {
                    btn = document.createElement('a');
                    btn.id = 'modal-download-btn';
                    btn.className = 'action-btn glow-effect';
                    btn.style.marginTop = '10px';
                    btn.style.marginBottom = '20px';
                    btn.style.display = 'inline-flex';
                    btn.innerHTML = `<span>${buttonLabel}</span><i class="fa-solid fa-arrow-up-right-from-square"></i>`;
                    passwordBox.parentNode.insertBefore(btn, passwordBox.nextSibling); // Insert after password box
                    downloadBtn = btn; // Update the reference
                }
                btn.innerHTML = `<span>${buttonLabel}</span><i class="fa-solid fa-${buttonLabel.includes('DOWNLOAD') ? 'download' : 'arrow-up-right-from-square'}"></i>`;
                btn.href = dataContent;
                btn.target = '_blank';
                btn.style.display = 'inline-flex';

            } else {
                // It's a password
                passwordBox.classList.remove('hidden');
                codeEl.textContent = dataContent;
                if (copyBtn) copyBtn.style.display = 'inline-flex';
            }
        }

        // Show
        resultModal.classList.remove('hidden');
        // Small delay to allow display:block to apply before opacity transition
        setTimeout(() => resultModal.classList.add('show'), 10);
    }

    function closeModal() {
        resultModal.classList.remove('show');
        setTimeout(() => resultModal.classList.add('hidden'), 300);
    }

    closeModalBtn.addEventListener('click', closeModal);
    resultModal.addEventListener('click', (e) => {
        if (e.target === resultModal) closeModal();
    });

    copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(modalPasswordCode.textContent).then(() => {
            const originalIcon = copyBtn.innerHTML;
            copyBtn.innerHTML = '<i class="fa-solid fa-check"></i>';
            setTimeout(() => copyBtn.innerHTML = originalIcon, 2000);
        });
    });

    // --- Drag & Drop ---
    dropZone.addEventListener('click', () => fileInput.click());

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        if (e.dataTransfer.files.length) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length) {
            handleFile(fileInput.files[0]);
        }
    });

    function handleFile(file) {
        if (!file.name.endsWith('.p12') && !file.name.endsWith('.pfx')) {
            log('error', 'Invalid file type. Please select a .p12 or .pfx file.');
            return;
        }
        selectedFile = file;

        // UI Update
        dropZone.querySelector('.upload-content h2').textContent = "File Selected";
        dropZone.querySelector('.upload-content p').style.display = 'none';
        dropZone.querySelector('.upload-icon').classList.remove('fa-file-shield');
        dropZone.querySelector('.upload-icon').classList.add('fa-check-circle');
        dropZone.querySelector('.upload-icon').style.color = 'var(--success)';

        fileInfo.querySelector('.filename').textContent = file.name;
        fileInfo.classList.remove('hidden');

        log('system', `File selected: ${file.name} (${(file.size / 1024).toFixed(2)} KB)`);
    }

    // --- Change View Drag & Drop ---
    dropZoneChange.addEventListener('click', () => fileInputChange.click());

    dropZoneChange.addEventListener('dragover', (e) => { e.preventDefault(); dropZoneChange.classList.add('drag-over'); });
    dropZoneChange.addEventListener('dragleave', () => dropZoneChange.classList.remove('drag-over'));

    dropZoneChange.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZoneChange.classList.remove('drag-over');
        if (e.dataTransfer.files.length) handleFileChange(e.dataTransfer.files[0]);
    });

    fileInputChange.addEventListener('change', () => {
        if (fileInputChange.files.length) handleFileChange(fileInputChange.files[0]);
    });

    function handleFileChange(file) {
        if (!file.name.endsWith('.p12') && !file.name.endsWith('.pfx')) {
            log('error', 'Invalid file type.');
            return;
        }
        selectedFileChange = file;

        // UI Update (Change View)
        dropZoneChange.querySelector('.upload-content h2').textContent = "File Ready";
        dropZoneChange.querySelector('.upload-content p').style.display = 'none';
        dropZoneChange.querySelector('.upload-icon').classList.remove('fa-file-shield');
        dropZoneChange.querySelector('.upload-icon').classList.add('fa-check-circle');
        dropZoneChange.querySelector('.upload-icon').style.color = 'var(--success)';

        fileInfoChange.querySelector('.filename').textContent = file.name;
        fileInfoChange.classList.remove('hidden');

        log('system', `(Change Tab) File selected: ${file.name}`);
    }

    // --- Change Password Action ---
    changeBtn.addEventListener('click', async () => {
        if (!selectedFileChange) {
            log('error', 'Please select a P12 file to change.');
            shake(dropZoneChange);
            return;
        }
        if (!oldPassInput.value || !newPassInput.value) {
            log('error', 'Please enter both old and new passwords.');
            return;
        }

        const formData = new FormData();
        formData.append('file', selectedFileChange);
        formData.append('old_password', oldPassInput.value);
        formData.append('new_password', newPassInput.value);

        changeBtn.disabled = true;
        changeBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> CHANGING...';
        log('system', 'Attempting to change password...');

        try {
            const res = await fetch('/api/change', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();

            if (res.ok && data.success) {
                log('success', `Password successfully changed!`);
                showModal('success', 'Password Changed!', 'The P12 file password has been updated. Download your file below.', data.path, true);
            } else {
                const error = data.error || 'Failed to change password.';
                log('error', typeof error === 'string' ? error : (error.message || 'Error'));
                handleApiError(error);
            }
        } catch (e) {
            log('error', 'Network error: ' + e.message);
        } finally {
            changeBtn.disabled = false;
            changeBtn.innerHTML = '<span>CHANGE PASSWORD</span><i class="fa-solid fa-rotate"></i>';
        }
    });

    // --- Mode Selection ---
    modeOptions.forEach(opt => {
        opt.addEventListener('change', updateSettingsUI);
    });

    function updateSettingsUI() {
        const mode = document.querySelector('input[name="attack-mode"]:checked').value;
        settingsArea.innerHTML = '';

        if (mode === 'dictionary') {
            // Disable Dictionary Mode for Web UI (User Request)
            showModal('error', 'Coming Next Update',
                'Dictionary mode is currently available only via Terminal or Desktop GUI\n\n' +
                'Run via Terminal:\n python3 main.py crack -p certificate_test.p12 -l passwords.txt \n\n' +
                'Run via GUI:\n python3 run_gui.py',
                null, false, 'CLOSE'
            );

            // Revert to Smart mode
            document.querySelector('input[value="smart"]').checked = true;
            settingsArea.innerHTML = ''; // Clear settings
            return;



        } else if (mode === 'brute_force') {
            settingsArea.innerHTML = `
                <div class="setting-group">
                    <label class="setting-label">Charset</label>
                    <input type="text" class="input-control" name="charset" value="abcdefghijklmnopqrstuvwxyz0123456789">
                </div>
                <div class="setting-group">
                    <label class="setting-label">Max Length (1-6)</label>
                    <input type="number" class="input-control" name="max_length" value="4" min="1" max="6">
                </div>
            `;
        }
    }

    // --- Cracking ---
    startBtn.addEventListener('click', async () => {
        if (startBtn.disabled) return;

        if (!selectedFile) {
            log('error', 'No file selected. Please drop a P12 file first.');
            shake(dropZone);
            return;
        }

        const mode = document.querySelector('input[name="attack-mode"]:checked').value;
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('mode', mode);

        // Append mode specific settings
        if (mode === 'brute_force') {
            const charset = document.querySelector('input[name="charset"]').value;
            const maxLen = document.querySelector('input[name="max_length"]').value;
            formData.append('charset', charset);
            formData.append('max_length', maxLen);
        }

        // Initialize Stream
        initLogStream();

        log('system', 'Starting cracking process...');
        startBtn.disabled = true;
        startBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> CRACKING...';

        try {
            const res = await fetch('/api/crack', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();

            if (!res.ok) {
                log('error', data.error || 'Unknown error occurred');
                startBtn.disabled = false;
                startBtn.innerHTML = '<span>START CRACKING</span><i class="fa-solid fa-play"></i>';
            }
        } catch (err) {
            log('error', 'Network error: ' + err.message);
            startBtn.disabled = false;
            startBtn.innerHTML = '<span>START CRACKING</span><i class="fa-solid fa-play"></i>';
        }
    });

    // --- Console ---
    function log(type, msg) {
        // Strip ANSI escape codes
        const cleanMsg = msg.replace(/\x1b\[[0-9;]*m/g, '');

        const div = document.createElement('div');
        div.className = `log - line ${type} `;
        div.textContent = `[${new Date().toLocaleTimeString()}] ${cleanMsg} `;
        consoleOutput.appendChild(div);
        consoleOutput.scrollTop = consoleOutput.scrollHeight;
    }

    function initLogStream() {
        if (eventSource) eventSource.close();

        eventSource = new EventSource('/api/stream');

        eventSource.onmessage = (e) => {
            const data = JSON.parse(e.data);
            if (data.log) {
                // Determine log type based on content
                let type = 'info';
                // Clean log for parsing
                const cleanLog = data.log.replace(/\x1b\[[0-9;]*m/g, '');

                if (cleanLog.includes('[!]') || cleanLog.includes('Error')) type = 'error';
                else if (cleanLog.includes('[+]') || cleanLog.includes('SUCCESS')) type = 'success';
                else if (cleanLog.includes('[-]')) type = 'warning';

                log(type, data.log); // Original log with potentially stripped colors in log() function

                // Check for completion events
                if (cleanLog.includes('[+] SUCCESS: Password found:')) {
                    const password = cleanLog.split('Password found:')[1].trim();
                    showModal('success', 'Password Found!', 'The password was successfully Cracked.', password);
                    resetBtn();
                } else if (cleanLog.includes('[-] Failed to find password') || cleanLog.includes('Attempts:')) {
                    // "Attempts:" is usually printed at the end of a brute force or dict run before success/fail
                    // But we want to catch the explicit failure log
                    if (cleanLog.includes('Failed to find password')) {
                        showModal('error', 'Crack Failed', 'Could not find the password with current settings.');
                        resetBtn();
                    }
                }
            }
        };

        eventSource.onerror = () => {
            eventSource.close();
        };
    }

    function resetBtn() {
        startBtn.disabled = false;
        startBtn.innerHTML = '<span>START CRACKING</span><i class="fa-solid fa-play"></i>';
    }

    clearConsoleBtn.addEventListener('click', () => {
        consoleOutput.innerHTML = '';
        log('system', 'Console cleared.');
    });

    // --- Helper Functions ---
    async function fetchUserProfile() {
        try {
            const res = await fetch('/api/user');
            const data = await res.json();

            if (data.error) {
                userProfileEl.innerHTML = '<div class="error">Failed to load profile</div>';
                return;
            }

            const isVip = data.plan && data.plan.name.toLowerCase().includes('vip');
            const planClass = isVip ? 'vip' : 'free';
            const limit = data.usage.limit === -1 ? 'Unlimited' : data.usage.limit;

            userProfileEl.innerHTML = `
                <div class="user-info" >
                    <h3>${data.name}</h3>
                    <span class="plan-badge ${planClass}">${data.plan.name}</span>
                    <div class="usage-stats">
                        <div class="stat-row">
                            <span>Daily Limit</span>
                            <span>${limit}</span>
                        </div>
                        <div class="stat-row">
                            <span>Remaining</span>
                            <span>${data.usage.remaining === -1 ? '∞' : data.usage.remaining}</span>
                        </div>
                    </div>
                </div >
                `;

            // Lock brute force if not VIP
            if (!isVip) {
                const bruteOpt = document.getElementById('brute-option');
                bruteOpt.style.opacity = '0.5';
                bruteOpt.style.pointerEvents = 'none';
                bruteOpt.querySelector('.desc').textContent = 'VIP Only (Locked)';
            }

        } catch (e) {
            console.error(e);
        }
    }

    function shake(element) {
        element.style.transform = 'translateX(10px)';
        setTimeout(() => element.style.transform = 'translateX(-10px)', 100);
        setTimeout(() => element.style.transform = 'translateX(10px)', 200);
        setTimeout(() => element.style.transform = 'translateY(0)', 300);
    }
});
