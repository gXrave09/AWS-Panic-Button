(function () {
  'use strict';

  const isFileOrigin = window.location.protocol === 'file:';
  const API_BASE = isFileOrigin ? 'http://localhost:8000' : '';

  // Header Elements
  const masterStatusPill = document.getElementById('master-status-pill');
  const masterStatusText = document.getElementById('master-status-text');

  // Master Buttons
  const enableLockdownBtn = document.getElementById('enable-lockdown-btn');
  const disableLockdownBtn = document.getElementById('disable-lockdown-btn');

  // Modal Elements
  const dangerModal = document.getElementById('danger-modal');
  const cancelDisableBtn = document.getElementById('cancel-disable-btn');
  const confirmDisableBtn = document.getElementById('confirm-disable-btn');

  // Resource Elements
  const s3StatusBadge = document.getElementById('s3-status-badge');
  const s3ToggleBtn = document.getElementById('s3-toggle-btn');

  const ec2StatusBadge = document.getElementById('ec2-status-badge');
  const ec2StatusLabel = document.getElementById('ec2-status-label');
  const ec2ToggleBtn = document.getElementById('ec2-toggle-btn');

  const snsStatusBadge = document.getElementById('sns-status-badge');
  const snsStatusLabel = document.getElementById('sns-status-label');
  const snsToggleBtn = document.getElementById('sns-toggle-btn');

  // Verification Elements
  const refreshBtn = document.getElementById('refresh-btn');
  const verifyUrl = document.getElementById('verify-url');
  const httpCodeBadge = document.getElementById('http-code-badge');
  const previewContent = document.getElementById('preview-content');

  // Check and update state
  async function checkSystemState() {
    let data = null;
    try {
      const controller = new AbortController();
      const id = setTimeout(() => controller.abort(), 2000);
      const res = await fetch(`${API_BASE}/verify-access`, { signal: controller.signal });
      clearTimeout(id);
      if (res.ok) {
        data = await res.json();
      }
    } catch (_) {}

    if (!data) return;

    // 1. Update Preview & URL
    verifyUrl.textContent = data.object_url;
    verifyUrl.href = data.object_url;
    previewContent.textContent = data.content_preview || 'No response content';

    // 2. S3 State
    const s3IsBlocked = data.s3_locked || data.http_status === 403 || data.http_status === 404;
    if (s3IsBlocked) {
      s3StatusBadge.textContent = 'Quarantined';
      s3StatusBadge.className = 'badge badge-safe';
      s3ToggleBtn.textContent = 'Restore Data';
      s3ToggleBtn.className = 'btn-subtle btn-subtle-restore';
    } else {
      s3StatusBadge.textContent = 'Exposed';
      s3StatusBadge.className = 'badge badge-danger';
      s3ToggleBtn.textContent = 'Block Access';
      s3ToggleBtn.className = 'btn-subtle btn-subtle-danger';
    }

    // 3. EC2 State
    const ec2IsBlocked = data.ec2_locked;
    if (ec2IsBlocked) {
      ec2StatusBadge.textContent = 'Stopped';
      ec2StatusBadge.className = 'badge badge-safe';
      ec2StatusLabel.textContent = 'Fleet Quarantined (Paused)';
      ec2ToggleBtn.textContent = 'Start Fleet';
      ec2ToggleBtn.className = 'btn-subtle btn-subtle-restore';
    } else {
      ec2StatusBadge.textContent = 'Running';
      ec2StatusBadge.className = 'badge badge-danger';
      ec2StatusLabel.textContent = data.ec2_status || '2 Instances (Active)';
      ec2ToggleBtn.textContent = 'Stop Fleet';
      ec2ToggleBtn.className = 'btn-subtle btn-subtle-danger';
    }

    // 4. SNS State
    if (data.sns_dispatched) {
      snsStatusBadge.textContent = 'Alert Sent';
      snsStatusBadge.className = 'badge badge-safe';
      if (snsStatusLabel && data.latest_sns_message) {
        snsStatusLabel.textContent = `Latest: ${data.latest_sns_message}`;
      }
    } else {
      snsStatusBadge.textContent = 'Standby';
      snsStatusBadge.className = 'badge badge-neutral';
      if (snsStatusLabel) {
        snsStatusLabel.textContent = 'Incident Notification Topic';
      }
    }

    // 5. Verification HTTP Badge
    if (s3IsBlocked) {
      httpCodeBadge.textContent = `${data.http_status || 404} Blocked`;
      httpCodeBadge.className = 'badge badge-safe';
    } else {
      httpCodeBadge.textContent = '200 OK Leaking';
      httpCodeBadge.className = 'badge badge-danger';
    }

    // 6. Master Status Pill
    if (s3IsBlocked && ec2IsBlocked) {
      masterStatusPill.className = 'status-pill status-pill-safe';
      masterStatusText.textContent = 'Secured · Lockdown Active';
    } else if (!s3IsBlocked && !ec2IsBlocked) {
      masterStatusPill.className = 'status-pill status-pill-danger';
      masterStatusText.textContent = 'Publicly Exposed';
    } else {
      masterStatusPill.className = 'status-pill status-pill-danger';
      masterStatusText.textContent = 'Partial Containment';
    }
  }

  // Master Enable Lockdown
  enableLockdownBtn.addEventListener('click', async () => {
    enableLockdownBtn.disabled = true;
    enableLockdownBtn.textContent = 'Locking down...';

    try {
      await fetch(`${API_BASE}/panic`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_bucket: 'confidential-company-data',
          operator: 'Console',
          reason: 'Emergency lockdown triggered'
        })
      });
    } catch (e) {
      console.warn('Lockdown error:', e);
    } finally {
      enableLockdownBtn.disabled = false;
      enableLockdownBtn.textContent = 'Enable Lockdown';
      await checkSystemState();
    }
  });

  // Master Disable Lockdown
  disableLockdownBtn.addEventListener('click', () => {
    dangerModal.classList.remove('hidden');
  });

  cancelDisableBtn.addEventListener('click', () => {
    dangerModal.classList.add('hidden');
  });

  dangerModal.addEventListener('click', (e) => {
    if (e.target === dangerModal) {
      dangerModal.classList.add('hidden');
    }
  });

  confirmDisableBtn.addEventListener('click', async () => {
    dangerModal.classList.add('hidden');
    disableLockdownBtn.disabled = true;
    disableLockdownBtn.textContent = 'Restoring...';

    try {
      await fetch(`${API_BASE}/reset`, { method: 'POST' });
    } catch (e) {
      console.warn('Reset error:', e);
    } finally {
      disableLockdownBtn.disabled = false;
      disableLockdownBtn.textContent = 'Restore Services';
      await checkSystemState();
    }
  });

  // S3 Toggle
  s3ToggleBtn.addEventListener('click', async () => {
    s3ToggleBtn.disabled = true;
    s3ToggleBtn.textContent = 'Updating...';

    try {
      await fetch(`${API_BASE}/toggle/s3`, { method: 'POST' });
    } catch (e) {
      console.warn('S3 toggle error:', e);
    } finally {
      s3ToggleBtn.disabled = false;
      await checkSystemState();
    }
  });

  // EC2 Toggle
  ec2ToggleBtn.addEventListener('click', async () => {
    ec2ToggleBtn.disabled = true;
    ec2ToggleBtn.textContent = 'Updating...';

    try {
      await fetch(`${API_BASE}/toggle/ec2`, { method: 'POST' });
    } catch (e) {
      console.warn('EC2 toggle error:', e);
    } finally {
      ec2ToggleBtn.disabled = false;
      await checkSystemState();
    }
  });

  // SNS Dispatch
  snsToggleBtn.addEventListener('click', async () => {
    snsToggleBtn.disabled = true;
    snsToggleBtn.textContent = 'Sending...';

    try {
      await fetch(`${API_BASE}/toggle/sns`, { method: 'POST' });
    } catch (e) {
      console.warn('SNS dispatch error:', e);
    } finally {
      snsToggleBtn.disabled = false;
      snsToggleBtn.textContent = 'Dispatch Alert';
      await checkSystemState();
    }
  });

  // Manual Refresh
  refreshBtn.addEventListener('click', checkSystemState);

  // Initial load & periodic poll
  checkSystemState();
  setInterval(checkSystemState, 4000);
})();
