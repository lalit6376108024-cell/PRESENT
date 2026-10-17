(() => {
  const video = document.getElementById('cameraPreview');
  if (!video) return;
  const canvas = document.getElementById('captureCanvas');
  const placeholder = document.getElementById('cameraPlaceholder');
  const status = document.getElementById('captureStatus');
  const mediaFile = document.getElementById('mediaFile');
  const kind = document.getElementById('memoryKind');
  const durationInput = document.getElementById('durationSeconds');
  const publish = document.getElementById('publishButton');
  const previewWrap = document.getElementById('capturedPreviewWrap');
  const capturedImage = document.getElementById('capturedImage');
  const capturedVideo = document.getElementById('capturedVideo');
  const recordingBadge = document.getElementById('recordingBadge');
  const startCamera = document.getElementById('startCamera');
  const takePhoto = document.getElementById('takePhoto');
  const startRecording = document.getElementById('startRecording');
  const stopRecording = document.getElementById('stopRecording');
  const stopCamera = document.getElementById('stopCamera');
  let stream = null, recorder = null, chunks = [], startedAt = 0, stopTimer = null, capturedUrl = null;

  function say(message) { status.textContent = message; }
  function clearCapture() {
    mediaFile.value = '';
    durationInput.value = '0';
    publish.disabled = true;
    previewWrap.hidden = true;
    capturedImage.hidden = true; capturedVideo.hidden = true;
    capturedImage.removeAttribute('src'); capturedVideo.removeAttribute('src');
    if (capturedUrl) URL.revokeObjectURL(capturedUrl);
    capturedUrl = null;
  }
  function setCapture(blob, filename, seconds) {
    if (!blob || !blob.size) { say('Capture failed. Please try again.'); return; }
    const dt = new DataTransfer();
    dt.items.add(new File([blob], filename, {type: blob.type || (kind.value === 'post' ? 'image/jpeg' : 'video/webm')}));
    mediaFile.files = dt.files;
    durationInput.value = String(seconds || 0);
    if (capturedUrl) URL.revokeObjectURL(capturedUrl);
    capturedUrl = URL.createObjectURL(blob);
    previewWrap.hidden = false;
    if (blob.type.startsWith('image/')) {
      capturedImage.src = capturedUrl; capturedImage.hidden = false; capturedVideo.hidden = true;
      kind.value = 'post'; say(`Photo ready (${(blob.size / 1024 / 1024).toFixed(1)} MB). Add a caption, then publish.`);
    } else {
      capturedVideo.src = capturedUrl; capturedVideo.hidden = false; capturedImage.hidden = true;
      kind.value = 'reel'; say(`Reel ready (${seconds}s, ${(blob.size / 1024 / 1024).toFixed(1)} MB). Add a caption, then publish.`);
    }
    publish.disabled = false;
  }
  async function openCamera() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) { say('Camera access needs a modern browser and a secure HTTPS connection. Open this app in Chrome or Safari.'); return; }
    try {
      stream = await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:'environment'},width:{ideal:1280},height:{ideal:720}},audio:true});
      video.srcObject = stream; placeholder.hidden = true; video.style.display = 'block';
      startCamera.disabled = true; takePhoto.disabled = false; startRecording.disabled = false; stopCamera.disabled = false;
      say('Camera is ready. Take a photo or record a reel.');
    } catch (err) {
      say(err && err.name === 'NotAllowedError' ? 'Camera permission was blocked. Allow camera and microphone access in your browser settings, then try again.' : 'Could not start the camera. Check that no other app is using it, then try again.');
    }
  }
  function closeCamera() {
    if (recorder && recorder.state === 'recording') recorder.stop();
    if (stream) stream.getTracks().forEach(track => track.stop());
    stream = null; video.srcObject = null; video.style.display = 'none'; placeholder.hidden = false;
    startCamera.disabled = false; takePhoto.disabled = true; startRecording.disabled = true; stopRecording.disabled = true; stopCamera.disabled = true;
    recordingBadge.hidden = true;
  }
  startCamera.addEventListener('click', openCamera);
  stopCamera.addEventListener('click', () => { closeCamera(); say('Camera closed. Your captured preview is still available.'); });
  takePhoto.addEventListener('click', () => {
    if (!stream || !video.videoWidth) { say('Wait for the camera preview, then take the photo.'); return; }
    canvas.width = video.videoWidth; canvas.height = video.videoHeight;
    canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height);
    canvas.toBlob(blob => setCapture(blob, 'wild-within-photo.jpg', 0), 'image/jpeg', 0.88);
  });
  startRecording.addEventListener('click', () => {
    if (!stream || !window.MediaRecorder) { say('Video recording is not supported by this browser. Try an updated Chrome or Safari.'); return; }
    let mime = '';
    for (const candidate of ['video/webm;codecs=vp9,opus','video/webm;codecs=vp8,opus','video/webm','video/mp4']) {
      if (MediaRecorder.isTypeSupported(candidate)) { mime = candidate; break; }
    }
    try {
      chunks = []; recorder = new MediaRecorder(stream, mime ? {mimeType:mime} : undefined);
      recorder.ondataavailable = event => { if (event.data && event.data.size) chunks.push(event.data); };
      recorder.onerror = () => { recordingBadge.hidden = true; say('Recording had an error. Please try again.'); };
      recorder.onstop = () => {
        clearTimeout(stopTimer); recordingBadge.hidden = true; stopRecording.disabled = true; startRecording.disabled = false; takePhoto.disabled = false;
        const seconds = Math.max(1, Math.min(90, Math.round((Date.now() - startedAt) / 1000)));
        const type = recorder.mimeType || (chunks[0] && chunks[0].type) || 'video/webm';
        setCapture(new Blob(chunks, {type}), type.includes('mp4') ? 'wild-within-reel.mp4' : 'wild-within-reel.webm', seconds);
      };
      recorder.start(500); startedAt = Date.now(); kind.value = 'reel';
      recordingBadge.hidden = false; startRecording.disabled = true; takePhoto.disabled = true; stopRecording.disabled = false;
      say('Recording… keep it under 90 seconds.');
      stopTimer = setTimeout(() => { if (recorder && recorder.state === 'recording') recorder.stop(); }, 90000);
    } catch (err) { say('Could not begin recording. Please try again or use a different browser.'); }
  });
  stopRecording.addEventListener('click', () => { if (recorder && recorder.state === 'recording') recorder.stop(); takePhoto.disabled = false; });
  document.getElementById('retakeCapture').addEventListener('click', () => { clearCapture(); say('Capture cleared. Take a new photo or record a new reel.'); });
  kind.addEventListener('change', () => {
    if (mediaFile.files.length) {
      const type = mediaFile.files[0].type;
      if ((kind.value === 'post' && !type.startsWith('image/')) || (kind.value === 'reel' && !type.startsWith('video/'))) {
        clearCapture(); say('The selected format changed, so capture a matching photo or reel.');
      }
    }
  });
  const caption = document.getElementById('memoryCaption');
  const count = document.getElementById('captionCount');
  caption.addEventListener('input', () => { count.textContent = `${caption.value.length} / 2200`; });
  document.getElementById('publishForm').addEventListener('submit', event => {
    if (!mediaFile.files.length) { event.preventDefault(); say('Capture a photo or record a reel before publishing.'); return; }
    if (kind.value === 'reel' && (Number(durationInput.value) < 1 || Number(durationInput.value) > 90)) { event.preventDefault(); say('Reels must be between 1 and 90 seconds.'); }
    else { publish.disabled = true; publish.textContent = 'Publishing…'; }
  });
  window.addEventListener('pagehide', () => { if (stream) stream.getTracks().forEach(track => track.stop()); if (capturedUrl) URL.revokeObjectURL(capturedUrl); });
})();
