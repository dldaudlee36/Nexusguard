// Only fixed loopback endpoints and whitelisted metadata are accepted.
const AGENT = 'http://127.0.0.1:8765';

function eventMetadata(message, sender) {
    const site = new URL(sender.url);
    if (!['http:', 'https:'].includes(site.protocol)) throw new Error('INVALID_SITE');
    const input = message.metadata;
    if (!input || typeof input !== 'object') throw new Error('INVALID_METADATA');
    const stamp = new Date(input.timestamp);
    if (typeof input.timestamp !== 'string' || !Number.isFinite(stamp.getTime())) throw new Error('INVALID_METADATA');
    const data = {target: site.hostname, timestamp: stamp.toISOString()};
    if (message.event_type === 'PASTE_ATTEMPT') {
        if (!Number.isSafeInteger(input.text_length) || input.text_length <= 0 || input.text_length > 100000000) throw new Error('INVALID_METADATA');
        data.text_length = input.text_length;
        return {path: '/paste-event', data, key: 'lastPaste'};
    }
    if (message.event_type === 'FILE_UPLOAD_ATTEMPT') {
        if (typeof input.file_name !== 'string' || input.file_name.length > 1024 || !Number.isSafeInteger(input.file_size) || input.file_size < 0) throw new Error('INVALID_METADATA');
        data.file_name = input.file_name;
        data.file_size = input.file_size;
        return {path: '/upload-event', data, key: 'lastUpload'};
    }
    throw new Error('INVALID_EVENT');
}

async function saveStatus(key, value) {
    try {
        const previous = (await chrome.storage.local.get(key))[key];
        if (!previous || previous.timestamp <= value.timestamp) await chrome.storage.local.set({[key]: value});
    } catch { /* A storage failure must not change the result of server delivery. */ }
}

async function deliver(message, sender) {
    let parsed;
    try { parsed = eventMetadata(message, sender); }
    catch (error) { return {status: 'failed', error: error.message}; }
    const record = {event_type: message.event_type, ...parsed.data};
    try {
        const response = await fetch(AGENT + parsed.path, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(parsed.data), signal: AbortSignal.timeout(12000),
            credentials: 'omit', redirect: 'error'
        });
        if (!response.ok) throw new Error(`HTTP_${response.status}`);
        const result = await response.json();
        if (result.status !== 'saved' || result.event_type !== message.event_type) throw new Error('INVALID_AGENT_RESPONSE');
        await saveStatus(parsed.key, {...record, status: 'saved'});
        return {status: 'saved', event_type: message.event_type};
    } catch (error) {
        const code = error.name === 'TimeoutError' || error.name === 'AbortError' ? 'TIMEOUT' :
            /^HTTP_|^INVALID_AGENT_RESPONSE$/.test(error.message) ? error.message : 'AGENT_UNREACHABLE';
        await saveStatus(parsed.key, {...record, status: 'failed', error: code});
        return {status: 'failed', error: code};
    }
}

async function diagnostics() {
    const result = {version: chrome.runtime.getManifest().version, agent: {ok: false}};
    try {
        const response = await fetch(AGENT + '/health', {signal: AbortSignal.timeout(3000), credentials: 'omit', redirect: 'error'});
        const health = await response.json();
        result.agent = {ok: response.ok && health.service === 'NexusGuardAgent' && /^3\./.test(health.version), version: health.version || '?'};
    } catch { /* The popup will explain that the Agent is not reachable. */ }
    Object.assign(result, await chrome.storage.local.get(['lastPaste', 'lastUpload']));
    return result;
}

chrome.runtime.onMessage.addListener((message, sender, respond) => {
    if (sender.id !== chrome.runtime.id) return false;
    if (message?.type === 'NEXUSGUARD_EVENT') {
        deliver(message, sender).then(respond, () => respond({status: 'failed', error: 'EXTENSION_ERROR'}));
        return true;
    }
    if (message?.type === 'NEXUSGUARD_STATUS' && sender.url?.startsWith(chrome.runtime.getURL(''))) {
        diagnostics().then(respond, () => respond({error: 'EXTENSION_ERROR'}));
        return true;
    }
    return false;
});
