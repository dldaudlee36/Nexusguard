/*
 * =====================================================================
 * NexusGuard Upload Detector - 크롬 확장 프로그램 (content script)
 * =====================================================================
 *
 * [이 파일이 하는 일]
 * 사용자가 웹페이지에서 파일을 첨부하려고 파일을 고르는 순간을 감지해서,
 * 파일 이름과 크기를 같은 PC에서 돌고 있는 Agent에게 알려준다.
 *
 *   [사용자가 파일 선택]
 *          ↓
 *   [이 스크립트가 감지]
 *          ↓ POST http://127.0.0.1:8765/upload-event
 *   [NexusGuardAgent.exe]
 *          ↓ POST
 *   [Railway 중앙 서버]
 *
 * [왜 Agent를 거치는가 — 서버로 바로 보내면 안 되나?]
 * 두 가지 이유가 있다.
 *   1) 브라우저 안에서는 윈도우 계정명이나 PC 이름을 알 수 없다.
 *      그 정보는 Agent만 알고 있으므로 Agent가 채워 넣어야 한다.
 *   2) 서버 주소나 인증 키를 확장 코드에 넣으면 누구나 열어볼 수 있다.
 *
 * [content script 란]
 * 확장 프로그램 중에서 '웹페이지 안에 직접 삽입되어 실행되는 코드'를 말한다.
 * 그래서 페이지의 요소나 사용자 동작을 직접 볼 수 있다.
 * manifest.json 의 matches 설정에 따라 모든 사이트에 삽입된다.
 *
 * [개인정보 관련]
 * 이 코드는 파일의 '이름과 크기'만 보낸다. 파일 내용을 읽거나 전송하는 코드는 없다.
 *
 * [감지 한계 — 시연 전 알아두어야 할 것]
 *   · <input type="file"> 형태의 일반 파일 선택창만 감지한다
 *   · 드래그앤드롭으로 올리는 것은 감지하지 못한다
 *   · 여러 파일을 골라도 첫 번째 파일만 보낸다 (files[0])
 *   · '파일을 골랐다'는 뜻이지 '업로드가 끝났다'는 뜻이 아니다.
 *     파일을 고르고 취소해도 로그는 남는다.
 *
 * [추가됨] 클립보드 붙여넣기는 이 파일 아래쪽 PASTE_ATTEMPT 감지 모듈이 담당한다.
 */

// change 이벤트: 입력 요소의 값이 바뀌었을 때 발생한다.
// 파일 선택창에서 파일을 고르면 이 이벤트가 뜬다.
//
// document 전체에 한 번만 걸어두는 이유:
// 페이지 안의 모든 파일 선택창에 일일이 붙이지 않아도,
// 이벤트가 위로 전달되는 성질(버블링) 덕분에 여기서 한꺼번에 받을 수 있다.
// 나중에 새로 생긴 요소도 자동으로 잡힌다.
document.addEventListener("change", async function (event) {
    const target = event.target;   // 실제로 값이 바뀐 요소

    // 파일 선택창이 맞는지, 그리고 실제로 파일이 골라졌는지 확인한다.
    // 페이지의 모든 입력창(텍스트, 체크박스 등)에서 change가 발생하므로
    // 파일 선택창만 골라내는 검사가 필요하다.
    if (
        target &&
        target.tagName === "INPUT" &&      // <input> 요소인가
        target.type === "file" &&          // 그중 파일 선택 종류인가
        target.files &&
        target.files.length > 0            // 실제로 파일이 골라졌는가 (취소하면 0)
    ) {
        const file = target.files[0];      // 첫 번째 파일만 사용

        // 개발자 도구(F12) 콘솔에서 동작을 확인할 수 있게 찍어둔다.
        // 확장이 제대로 설치됐는지 점검할 때 유용하다.
        console.log("[NexusGuard] FILE_UPLOAD_ATTEMPT");
        console.log("사이트:", window.location.hostname);
        console.log("파일명:", file.name);
        console.log("파일 크기:", file.size);

        // Agent에게 보낼 내용. 파일 내용은 포함하지 않는다.
        const logData = {
            target: window.location.hostname,   // 어느 사이트에서 올리려 했는가
            file_name: file.name,
            file_size: file.size                // 바이트 단위
        };

        try {
            // 127.0.0.1 은 '내 컴퓨터 자신'을 가리키는 주소다.
            // 인터넷으로 나가지 않고 같은 PC의 Agent에게만 전달된다.
            //
            // await 는 '응답이 올 때까지 기다린다'는 뜻이다.
            // 함수 앞에 async 가 붙어 있어야 쓸 수 있다.
            const response = await fetch(
                "http://127.0.0.1:8765/upload-event",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify(logData)   // 객체를 JSON 문자열로 변환
                }
            );

            if (response.ok) {
                console.log(
                    "[NexusGuard] Agent 전달 성공"
                );
            } else {
                // 서버에는 닿았지만 오류 응답을 받은 경우 (예: 404)
                console.log(
                    "[NexusGuard] Agent 오류:",
                    response.status
                );
            }

        } catch (error) {
            // 서버에 아예 닿지 못한 경우.
            // 대부분 Agent가 꺼져 있을 때 발생한다.
            //
            // 중요: 여기서 오류를 잡아주지 않으면 브라우저 콘솔에 빨간 오류가 뜨고,
            //      사용자가 쓰던 사이트에 문제가 생긴 것처럼 보일 수 있다.
            //      보안 도구가 업무를 방해해서는 안 되므로 조용히 넘어간다.
            console.log(
                "[NexusGuard] Agent 연결 실패:",
                error
            );
        }
    }
});


/*
 * =====================================================================
 * NexusGuard Paste Detector - 붙여넣기 감지 모듈  [추가됨]
 * =====================================================================
 *
 * [왜 필요한가]
 * 2023년 삼성에서 있었던 ChatGPT 유출 3건은 전부 파일 업로드가 아니라
 * '소스코드와 회의록을 복사해서 붙여넣은 것'이었다.
 * 위쪽 파일첨부 감지만으로는 이 통로가 그대로 뚫려 있다.
 *
 * [설계 원칙 — 반드시 지킬 것]
 *
 *  1) 붙여넣기를 막지 않는다.
 *     preventDefault() 를 호출하지 않으므로 붙여넣기는 정상적으로 이뤄진다.
 *     이 엔진은 판정하고 알릴 뿐 차단은 관리자가 한다는 원칙과 같다.
 *     보안 도구가 업무를 방해하기 시작하면 사람들은 도구를 끄게 된다.
 *
 *  2) 붙여넣은 내용을 전송하지 않는다.
 *     보안 도구가 유출 통로가 되면 안 된다.
 *     밖으로 나가는 값은 '문자 수'와 '패턴 검출 개수'뿐이다.
 *     원문은 이 함수 안에서만 존재하고 끝나면 사라진다.
 *
 *  3) 감시 대상 AI 도메인에서만 동작한다.
 *     그 외 사이트에서는 리스너를 아예 등록하지 않는다.
 *     사내 메일이나 업무 시스템에 붙여넣는 것까지 볼 이유가 없다.
 *
 *  4) 200자 미만은 무시한다.
 *     짧은 질문 문장까지 전부 기록하면 로그만 쌓이고 의미가 없다.
 *
 *  5) capture 단계로 등록한다. (addEventListener 의 세 번째 인자 true)
 *     이벤트는 바깥에서 안쪽으로 내려갔다가(capture) 다시 올라온다(bubble).
 *     사이트가 stopPropagation() 으로 이벤트를 가로채면 올라오는 단계에서는
 *     우리 리스너까지 도달하지 못한다. 내려가는 단계에서 먼저 받으면 그 영향을 안 받는다.
 *
 * [사생활 관련 — 발표에서 함께 말할 것]
 * 패턴 검출은 그 자체로 내용에 대한 신호다. "주민번호 형태 3건"도 내용을 본 결과다.
 * 실제 배포한다면 직원 사전 고지가 필요하다.
 * =====================================================================
 */

// 감시 대상 AI 도메인. 이 목록에 없는 사이트에서는 아무것도 하지 않는다.
const NG_WATCHED_AI_DOMAINS = [
    "chatgpt.com",
    "openai.com",
    "claude.ai",
    "gemini.google.com",
    "perplexity.ai",
    "copilot.microsoft.com"
];

// 이 길이 미만은 무시한다. 짧은 질문까지 기록하면 로그만 쌓인다.
const NG_MIN_PASTE_LENGTH = 200;

/*
 * 현재 사이트가 감시 대상인지 확인한다.
 *
 * endsWith("." + domain) 을 함께 보는 이유는 서브도메인 때문이다.
 * chat.openai.com 도 openai.com 으로 취급해야 한다.
 * 단순히 includes 로 검사하면 evil-chatgpt.com.attacker.net 같은
 * 가짜 도메인까지 걸리므로 그렇게 하면 안 된다.
 */
function ngIsWatchedHost(hostname) {
    const host = String(hostname || "").toLowerCase();

    return NG_WATCHED_AI_DOMAINS.some(function (domain) {
        return host === domain || host.endsWith("." + domain);
    });
}

/*
 * 카드번호 체크섬(Luhn) 검증.
 *
 * 실제 카드번호는 마지막 자리가 검사용 숫자라서 정해진 계산식을 통과한다.
 * 이 검사를 넣지 않으면 주문번호나 운송장번호 같은 아무 16자리 숫자가
 * 전부 카드번호로 잡힌다.
 *
 * 계산 방법: 오른쪽부터 한 칸 건너 두 배로 만들고(9를 넘으면 9를 뺀다)
 *           전부 더한 값이 10으로 나누어떨어지면 유효한 번호다.
 */
function ngLuhnValid(digits) {
    let sum = 0;
    let alternate = false;

    for (let i = digits.length - 1; i >= 0; i--) {
        let n = parseInt(digits.charAt(i), 10);

        if (alternate) {
            n *= 2;
            if (n > 9) {
                n -= 9;
            }
        }

        sum += n;
        alternate = !alternate;
    }

    return sum % 10 === 0;
}

/*
 * 민감정보 패턴이 몇 건 들어 있는지만 센다.
 * 매칭된 문자열 자체는 저장하지도 반환하지도 않는다.
 *
 * [오탐을 막기 위해 신경 쓴 것]
 *
 *  · 주민등록번호: 월(01~12)과 일(01~31)까지 확인한다.
 *    그냥 13자리 숫자를 받으면 자바스크립트 타임스탬프(예: 1757404800000)가 걸린다.
 *    에러 로그를 붙여넣었을 뿐인데 주민번호로 잡히면 곤란하다.
 *
 *  · 카드번호: 자릿수만 맞으면 세지 않고 Luhn 검증을 통과한 것만 센다.
 *    그냥 16자리를 받으면 주문번호 2026090912345678 같은 것이 걸린다.
 *
 *  · 앞뒤의 (?<![0-9]) 와 (?![0-9]) : 더 긴 숫자열의 일부가 잘려서
 *    잡히는 것을 막는다. 앞이나 뒤에 숫자가 더 붙어 있으면 매칭하지 않는다.
 *
 * ※ (?<! ) 형태의 lookbehind 문법은 Chrome 62 이상에서 동작한다.
 */
function ngCountPatternHits(text) {
    const simplePatterns = {
        // 주민등록번호: YYMMDD + 성별코드(1~4) + 6자리
        rrn: /(?<![0-9])\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[-\s]?[1-4]\d{6}(?![0-9])/g,
        // 이메일
        email: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
        // 국내 휴대전화 번호
        phone: /(?<![0-9])01[016-9][-\s]?\d{3,4}[-\s]?\d{4}(?![0-9])/g
    };

    const hits = {};

    for (const key in simplePatterns) {
        const matched = text.match(simplePatterns[key]);
        hits[key] = matched ? matched.length : 0;   // 개수만 남기고 내용은 버린다
    }

    // 카드번호는 형태가 맞는 후보를 먼저 뽑고, Luhn 을 통과한 것만 센다.
    const cardCandidates = text.match(
        /(?<![0-9])(?:\d{4}[-\s]?){3}\d{4}(?![0-9])/g
    ) || [];

    let cardCount = 0;

    for (const candidate of cardCandidates) {
        const digits = candidate.replace(/[^0-9]/g, "");   // 하이픈·공백 제거
        if (digits.length === 16 && ngLuhnValid(digits)) {
            cardCount++;
        }
    }

    hits.card = cardCount;

    return hits;
}

/*
 * Agent에게 붙여넣기 이벤트를 보낸다.
 * 위쪽 파일첨부와 같은 주소(127.0.0.1:8765/upload-event)를 쓴다.
 */
async function ngSendPasteEvent(logData) {
    try {
        const response = await fetch(
            "http://127.0.0.1:8765/upload-event",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(logData)
            }
        );

        if (response.ok) {
            console.log(
                "[NexusGuard] Agent 전달 성공 (PASTE_ATTEMPT)"
            );
        } else {
            console.log(
                "[NexusGuard] Agent 오류:",
                response.status
            );
        }

    } catch (error) {
        // Agent가 꺼져 있는 경우가 대부분이다. 조용히 넘어간다.
        console.log(
            "[NexusGuard] Agent 연결 실패:",
            error
        );
    }
}

// 감시 대상 도메인이 아니면 리스너를 아예 등록하지 않는다.
// 조건문 안에서 등록하므로, 다른 사이트에서는 이 코드가 존재하지도 않는 것과 같다.
if (ngIsWatchedHost(window.location.hostname)) {

    document.addEventListener("paste", function (event) {
        // 이 안에 preventDefault() 는 없다. 붙여넣기는 그대로 진행된다.
        try {
            // clipboardData 에 사용자가 붙여넣으려는 내용이 들어 있다.
            const clipboard = event.clipboardData || window.clipboardData;

            if (!clipboard) {
                return;   // 클립보드를 못 읽는 환경이면 아무것도 하지 않는다
            }

            const text = clipboard.getData("text/plain") || "";

            if (text.length < NG_MIN_PASTE_LENGTH) {
                return;   // 짧은 붙여넣기는 무시
            }

            const patternHits = ngCountPatternHits(text);

            // 밖으로 나가는 것은 이 네 가지뿐이다. text 는 여기 없다.
            const logData = {
                event_type: "PASTE_ATTEMPT",
                target: window.location.hostname,
                text_length: text.length,
                pattern_hits: patternHits
            };

            console.log("[NexusGuard] PASTE_ATTEMPT");
            console.log("사이트:", logData.target);
            console.log("문자 수:", logData.text_length);
            console.log("패턴 검출 개수:", patternHits);
            // 콘솔에도 원문은 찍지 않는다. 개발자 도구를 열면 보이기 때문이다.

            ngSendPasteEvent(logData);

        } catch (error) {
            // 감지에 실패해도 사용자의 붙여넣기는 이미 정상 진행된 상태다.
            console.log(
                "[NexusGuard] paste 감지 오류:",
                error
            );
        }
    }, true);   // ← 이 true 가 capture 단계 등록을 뜻한다
}
