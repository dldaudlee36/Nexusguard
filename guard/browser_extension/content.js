/**
 * NexusGuard Browser Extension - Content Script
 * 감지 이벤트:
 *   1. FILE_UPLOAD_ATTEMPT — <input type="file"> 파일 선택
 *   2. FILE_UPLOAD_ATTEMPT — 드래그 앤 드롭 (ondrop)
 *   3. PASTE_ATTEMPT       — 클립보드 붙여넣기 (paste)
 */

const AGENT_URL = "http://127.0.0.1:8765/upload-event";

/**
 * Railway 에이전트로 이벤트 비동기 전송
 * @param {string} eventType - "FILE_UPLOAD_ATTEMPT" | "PASTE_ATTEMPT"
 * @param {Object} extra - 추가 메타데이터 (file_name, file_size 등)
 */
async function sendToAgent(eventType, extra = {}) {
    const payload = {
        target: window.location.hostname,
        event_type: eventType,
        ...extra
    };

    console.log(`[NexusGuard] ${eventType}`, payload);

    try {
        const response = await fetch(AGENT_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            console.log("[NexusGuard] Agent 전달 성공");
        } else {
            console.log("[NexusGuard] Agent 오류:", response.status);
        }
    } catch (error) {
        console.log("[NexusGuard] Agent 연결 실패:", error);
    }
}


/* ─────────────────────────────────────────────────────────────────
   1. FILE_UPLOAD_ATTEMPT — <input type="file"> change 이벤트
   ───────────────────────────────────────────────────────────────── */
document.addEventListener("change", async function (event) {
    const target = event.target;

    if (
        target &&
        target.tagName === "INPUT" &&
        target.type === "file" &&
        target.files &&
        target.files.length > 0
    ) {
        const file = target.files[0];

        await sendToAgent("FILE_UPLOAD_ATTEMPT", {
            file_name: file.name,
            file_size: file.size
        });
    }
});


/* ─────────────────────────────────────────────────────────────────
   2. FILE_UPLOAD_ATTEMPT — 드래그 앤 드롭 (ondrop)
   AI 챗 인터페이스(ChatGPT, Claude 등)에서 파일을 끌어다 놓는 행위 탐지
   ───────────────────────────────────────────────────────────────── */
document.addEventListener("drop", async function (event) {
    const dt = event.dataTransfer;
    if (!dt || !dt.files || dt.files.length === 0) return;

    const file = dt.files[0];

    console.log("[NexusGuard] DRAG_DROP_FILE_DETECTED");
    console.log("사이트:", window.location.hostname);
    console.log("파일명:", file.name);
    console.log("파일 크기:", file.size);

    await sendToAgent("FILE_UPLOAD_ATTEMPT", {
        file_name: file.name,
        file_size: file.size,
        drop_method: "drag_and_drop"
    });
}, true /* useCapture: 최상위에서 선점하여 AI 사이트의 자체 핸들러보다 먼저 실행 */);


/* ─────────────────────────────────────────────────────────────────
   3. PASTE_ATTEMPT — 클립보드 붙여넣기
   대용량 텍스트 붙여넣기(1KB 이상)를 잠재적 데이터 유출로 감지
   ───────────────────────────────────────────────────────────────── */
document.addEventListener("paste", async function (event) {
    const cd = event.clipboardData || window.clipboardData;
    if (!cd) return;

    // 붙여넣기 데이터 추출
    const pastedText = cd.getData("text") || "";
    const pastedSize = new Blob([pastedText]).size;

    // 파일 붙여넣기 (이미지 등)
    if (cd.files && cd.files.length > 0) {
        const file = cd.files[0];
        console.log("[NexusGuard] PASTE_FILE_DETECTED:", file.name, file.size);
        await sendToAgent("PASTE_ATTEMPT", {
            file_name: file.name,
            file_size: file.size,
            paste_method: "clipboard_file"
        });
        return;
    }

    // 텍스트 붙여넣기: 1KB(1024 bytes) 이상만 보고 (노이즈 최소화)
    if (pastedSize >= 1024) {
        console.log("[NexusGuard] PASTE_TEXT_DETECTED — 크기:", pastedSize, "bytes");
        await sendToAgent("PASTE_ATTEMPT", {
            file_name: null,
            file_size: pastedSize,
            paste_method: "clipboard_text",
            preview: pastedText.substring(0, 80) + (pastedText.length > 80 ? "..." : "")
        });
    }
}, true /* useCapture */);