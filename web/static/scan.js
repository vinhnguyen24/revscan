/* Scan page: drag & drop, upload with progress, then redirect to the report. */
(() => {
  const drop = document.getElementById('drop');
  const input = document.getElementById('file');
  const pick = document.getElementById('pick');
  const progress = document.getElementById('progress');
  const bar = document.getElementById('bar');
  if (!drop || !input) return;

  const mode = () => (document.querySelector('input[name=mode]:checked') || {}).value || 'static';

  pick.addEventListener('click', (e) => {
    e.preventDefault();
    input.click();
  });

  ['dragenter', 'dragover'].forEach((evt) =>
    drop.addEventListener(evt, (e) => {
      e.preventDefault();
      drop.classList.add('hover');
    })
  );
  ['dragleave', 'drop'].forEach((evt) =>
    drop.addEventListener(evt, (e) => {
      e.preventDefault();
      drop.classList.remove('hover');
    })
  );
  drop.addEventListener('drop', (e) => {
    const file = e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) upload(file);
  });
  input.addEventListener('change', () => {
    if (input.files && input.files[0]) upload(input.files[0]);
  });

  function setProgress(pct) {
    progress.hidden = false;
    bar.style.width = Math.max(3, Math.min(100, pct)) + '%';
  }

  function fail(message) {
    progress.hidden = true;
    const box = document.getElementById('result');
    // textContent, not innerHTML: the message can come from the engine.
    box.textContent = '';
    const alert = document.createElement('div');
    alert.className = 'alert bad';
    alert.textContent = message;
    box.appendChild(alert);
  }

  const msg = {
    tooLarge: drop.dataset.msgTooLarge || 'File exceeds 150MB limit.',
    badExt: drop.dataset.msgBadExt || 'Only .exe, .dll, .bin, .sys are accepted.',
    errPrefix: drop.dataset.msgErrPrefix || 'Error',
    netErr: drop.dataset.msgNetErr || 'Could not reach server.',
  };

  function upload(file) {
    if (file.size > 150 * 1024 * 1024) return fail(msg.tooLarge);
    const ext = (file.name.split('.').pop() || '').toLowerCase();
    if (!['exe', 'dll', 'bin', 'sys'].includes(ext)) return fail(msg.badExt);

    const xhr = new XMLHttpRequest();
    xhr.open('POST', `/api/scan?mode=${encodeURIComponent(mode())}`);
    xhr.setRequestHeader('x-filename', file.name);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) setProgress((e.loaded / e.total) * 85);
    };
    xhr.onload = () => {
      setProgress(100);
      let json = null;
      try { json = JSON.parse(xhr.responseText); } catch { /* ignore */ }
      if (!json || !json.ok) {
        return fail((json && json.error && json.error.message) || `${msg.errPrefix} ${xhr.status}`);
      }
      location.href = json.data.url;
    };
    xhr.onerror = () => fail(msg.netErr);
    xhr.send(file);
  }
})();
