const element = id => document.getElementById(id);
const failures = {
    AGENT_UNREACHABLE: 'Agent에 연결하지 못했습니다. start-agent.bat을 실행하세요.',
    HTTP_502: 'Agent는 받았지만 Railway 저장에 실패했습니다. 인터넷 연결을 확인하세요.',
    HTTP_400: '이벤트 형식이 맞지 않습니다. 확장과 Agent 버전을 확인하세요.',
    HTTP_404: '이전 Agent가 실행 중입니다. Agent v3를 실행하세요.',
    TIMEOUT: '전송 시간이 초과됐습니다. 연결 후 다시 붙여넣으세요.',
    INVALID_AGENT_RESPONSE: '다른 프로그램이 연결 포트를 사용 중입니다.'
};
async function refresh() {
    element('refresh').disabled = true;
    try {
        const status = await chrome.runtime.sendMessage({type: 'NEXUSGUARD_STATUS'});
        if (!status || status.error) throw new Error('EXTENSION_ERROR');
        element('version').textContent = `확장 ${status.version}`;
        element('agent').textContent = status.agent.ok ? `연결됨 · Agent ${status.agent.version}` : '연결 안 됨 · start-agent.bat을 실행하세요.';
        element('agent').className = status.agent.ok ? 'ok' : 'failed';
        const paste = status.lastPaste;
        if (!paste) {
            element('paste').textContent = '아직 감지 기록이 없습니다. ChatGPT 탭을 새로고침하고 붙여넣으세요.';
            element('paste').className = '';
            element('details').textContent = '';
        } else {
            element('paste').textContent = paste.status === 'saved' ? 'Railway 서버 저장 완료' : failures[paste.error] || `전송 실패 (${paste.error})`;
            element('paste').className = paste.status === 'saved' ? 'ok' : 'failed';
            element('details').textContent = `${paste.target} · ${paste.text_length}자 · ${new Date(paste.timestamp).toLocaleString('ko-KR')}`;
        }
    } catch {
        element('agent').textContent = '확장을 새로고침한 뒤 다시 열어주세요.';
        element('agent').className = 'failed';
    } finally { element('refresh').disabled = false; }
}
element('refresh').addEventListener('click', refresh);
void refresh();
