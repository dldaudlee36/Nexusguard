/*
 * NexusGuard - 붙여넣기 패턴 검출 오탐 테스트
 *
 * 실행 방법:
 *   1) 이 파일을 Nexusguard-main 폴더 안에 둔다
 *   2) 터미널에서:  node test_pattern_falsepositive.js
 *
 * guard/browser_extension/content.js 를 이 파일 위치 기준으로 찾습니다.
 */

const fs = require('fs');
const path = require('path');

const candidates = [
  path.join(__dirname, 'browser_extension', 'content.js'),
  path.join(__dirname, 'guard', 'browser_extension', 'content.js'),
  path.join(__dirname, '..', 'browser_extension', 'content.js'),
  path.join(__dirname, '..', 'guard', 'browser_extension', 'content.js'),
  path.join(__dirname, 'Nexusguard-main', 'guard', 'browser_extension', 'content.js'),
  path.join(__dirname, 'content.js'),
];

const contentPath = candidates.find(p => fs.existsSync(p));

if (!contentPath) {
  console.error('content.js 를 찾을 수 없습니다. 확인한 위치:');
  candidates.forEach(p => console.error('  - ' + p));
  console.error('\n이 파일을 Nexusguard-main 폴더 안에 두고 다시 실행하세요.');
  process.exit(1);
}

console.log('검사 대상: ' + contentPath + '\n');

const src = fs.readFileSync(contentPath, 'utf8');
const start = src.indexOf('function ngLuhnValid');
const end = src.indexOf('async function ngSendPasteEvent');

if (start === -1 || end === -1) {
  console.error('content.js 에서 패턴 검출 함수를 찾지 못했습니다. 수정본이 맞는지 확인하세요.');
  process.exit(1);
}

eval(src.slice(start, end));

let fail = 0;

function run(name, text, want) {
  const h = ngCountPatternHits(text);
  const got = { rrn: h.rrn, card: h.card, email: h.email, phone: h.phone };
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) fail++;
  console.log(
    `${ok ? 'OK  ' : 'FAIL'} ${name.padEnd(26)} rrn=${h.rrn} card=${h.card} email=${h.email} phone=${h.phone}` +
    (ok ? '' : '   기대: ' + JSON.stringify(want))
  );
}

console.log('=== 정상 내용 (오탐이 없어야 함) ===');

run('일반 한글 기획문서', `이번 분기 마케팅 전략은 다음과 같습니다. 1분기 대비 2분기 전환율이 3.4% 상승했고,
목표 KPI는 12만 세션입니다. 채널별 검색 42%, SNS 31%, 직접유입 27% 비중입니다.`,
  { rrn: 0, card: 0, email: 0, phone: 0 });

run('파이썬 코드', `def calc(events, weights=None):
    if weights is None:
        weights = {"db": 2, "dns": 2, "upload": 4}
    return min(sum(w for w in weights.values()), 100)`,
  { rrn: 0, card: 0, email: 0, phone: 0 });

run('에러 로그(타임스탬프)', `[2026-09-09T10:12:33.412Z] ERROR request_id=1757404800000 latency=1284ms
[2026-09-09T10:12:34.980Z] WARN retry 2/3 upstream=10.0.0.30:3306
request_id=1757404812345 status=502 bytes=284719`,
  { rrn: 0, card: 0, email: 0, phone: 0 });

run('SQL / 주문번호', `INSERT INTO orders VALUES (1002938477, '2026090912345678', 48900.00, NOW());
운송장번호 1234567890123 주문번호 2026 0909 1234 5678`,
  { rrn: 0, card: 0, email: 0, phone: 0 });

run('고객센터 번호', `고객센터 1588-1234 / 1666-9876 운영시간 09:00-18:00 연중무휴`,
  { rrn: 0, card: 0, email: 0, phone: 0 });

run('UUID / 해시', `id=550e8400-e29b-41d4-a716-446655440000
sha=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`,
  { rrn: 0, card: 0, email: 0, phone: 0 });

run('영문 이메일 초안', `Hi team, reply to hyesung.kang@example.com or platform-oncall@example.com`,
  { rrn: 0, card: 0, email: 2, phone: 0 });

console.log('\n=== 실제 민감정보 (탐지되어야 함) ===');

run('주민번호 2건', `홍길동 900101-1234567 / 김철수 851231-2345678 서울시 강남구`,
  { rrn: 2, card: 0, email: 0, phone: 0 });

run('주민번호 하이픈 없음', `고객식별 9001011234567 등록완료`,
  { rrn: 1, card: 0, email: 0, phone: 0 });

run('카드번호(Luhn 유효)', `결제카드 4242-4242-4242-4242 / 5500 0055 5555 5559`,
  { rrn: 0, card: 2, email: 0, phone: 0 });

run('휴대폰 2건', `연락처 010-1234-5678 / 01098765432`,
  { rrn: 0, card: 0, email: 0, phone: 2 });

run('고객명단 유출 시나리오', `홍길동 900101-1234567 010-1234-5678 hong@corp.co.kr 4111-1111-1111-1111
김영희 880315-2345678 010-9876-5432 kim@corp.co.kr`,
  { rrn: 2, card: 1, email: 2, phone: 2 });

console.log(fail === 0 ? '\n전체 PASS (13/13)' : `\n실패 ${fail}건`);
process.exit(fail ? 1 : 0);
