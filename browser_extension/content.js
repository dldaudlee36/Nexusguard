// NexusGuard 3.1: capture metadata here, send HTTP only from the extension worker.
(() => {
    if (globalThis.__nexusguardV31Installed) return;
    globalThis.__nexusguardV31Installed = true;

    async function sendEvent(path, metadata) {
        try {
            const result = await chrome.runtime.sendMessage({
                type: 'NEXUSGUARD_EVENT',
                event_type: path === '/paste-event' ? 'PASTE_ATTEMPT' : 'FILE_UPLOAD_ATTEMPT',
                metadata
            });
            if (!result || result.status !== 'saved') {
                console.warn('[NexusGuard] 전송 실패', result?.error || '확장 새로고침 필요');
                return;
            }
            console.log('[NexusGuard] Railway 저장 성공', result.event_type);
        } catch (error) {
            console.warn('[NexusGuard] 확장 연결 실패 — 확장과 사이트를 새로고침하세요.', error.name);
        }
    }

    document.addEventListener('change', function (event) {
        const target = event.composedPath?.()[0] || event.target;
        if (!event.isTrusted || !target || target.tagName !== 'INPUT' || target.type !== 'file') return;
        for (const file of Array.from(target.files || [])) {
            const metadata = {
                target: window.location.hostname,
                file_name: file.name,
                file_size: file.size,
                timestamp: new Date().toISOString()
            };
            console.log('[NexusGuard] FILE_UPLOAD_ATTEMPT', metadata);
            void sendEvent('/upload-event', metadata);
        }
    }, true);

    document.addEventListener('paste', function (event) {
        if (!event.isTrusted || !event.clipboardData) return;
        const target = event.composedPath?.()[0] || event.target;
        if (target && target.tagName === 'INPUT' && target.type === 'password') return;
        const textLength = Array.from(event.clipboardData.getData('text/plain') || '').length;
        if (textLength === 0) return;
        const metadata = {
            target: window.location.hostname,
            timestamp: new Date().toISOString(),
            text_length: textLength
        };
        console.log('[NexusGuard] PASTE_ATTEMPT', metadata);
        void sendEvent('/paste-event', metadata);
    }, true);
    console.log('[NexusGuard] 붙여넣기 감지 준비 완료 · 확장 3.1.0');
})();
