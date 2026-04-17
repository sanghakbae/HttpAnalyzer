# HTTP Analyzer

`HTTP Analyzer`는 브라우저/클라이언트에서 발생한 HTTP 트래픽을 캡처하고, 요청/응답을 눈으로 확인하면서 보안 관점에서 빠르게 분류할 수 있도록 만든 로컬 분석 도구입니다.

이 프로젝트는 세 가지 축으로 구성됩니다.

- `mitmproxy`로 실시간 트래픽을 가로채고 수정/관찰
- `Node + Express` 서버로 캡처 상태, HAR 분석, 리플레이, Supabase 저장 처리
- `React + Vite` 프런트엔드로 요청/응답 확인, 보안 패턴 분석, 리포트 출력

## 핵심 기능

- 실시간 HTTP 요청/응답 캡처
- 요청/응답 헤더 및 바디 확인
- 특정 요청 재전송(Replay)
- HAR 파일 업로드 및 성능/호스트/상태코드 분석
- 보안 패턴 탐지 및 `OWASP Top 10` 기준 요약
- 엔드포인트 우선순위 정리
- `Before / After` 비교용 Diff
- `HTML / JSON / Markdown / CSV` 리포트 출력
- 분석 결과를 Supabase 테이블에 저장

## 현재 UI에서 지원하는 보안 분석

프런트에서 캡처된 요청/응답을 기반으로 아래 항목들을 탐지합니다.

- 민감정보 URL 노출
- 응답 본문 비밀값 노출
- 요청 본문 민감정보 포함
- 위험한 CORS 설정
- 세션 쿠키 속성 누락(`HttpOnly`, `Secure`, `SameSite`)
- 보안 헤더 누락(`CSP`, `HSTS`, `X-Frame-Options`, `Referrer-Policy`, `X-Content-Type-Options`)
- 서버 배너/버전 노출
- 스택트레이스/상세 오류 노출
- 디렉터리 인덱싱 노출
- 캐시 정책 부족
- SQLi / XSS / SSRF / Path Traversal / Command Injection / Open Redirect 흔적
- Basic 인증 사용 흔적

각 finding은 다음 정보를 함께 보여줍니다.

- 심각도
- OWASP 분류
- Evidence
- Guide
- Remediation
- Reproduction Checklist
- PoC Template

## 프로젝트 구조

```text
.
├─ proxy/
│  ├─ modify_request.py
│  ├─ requirements.txt
│  └─ rules.json
├─ server/
│  └─ index.js
├─ src/
│  ├─ App.jsx
│  ├─ main.jsx
│  ├─ styles.css
│  └─ lib/supabase.js
├─ supabase/
│  └─ migrations/
├─ .env.example
├─ package.json
└─ README.md
```

주요 파일 설명:

- `proxy/modify_request.py`
  `mitmproxy` 애드온입니다. `proxy/rules.json` 규칙을 읽어서 요청 바디를 수정하고 응답을 출력합니다.
- `server/index.js`
  프론트 API 서버입니다. 캡처 상태 조회, 리플레이, HAR 분석, Supabase 저장을 처리합니다.
- `src/App.jsx`
  메인 UI입니다. 실시간 요청 목록, 보안 finding, 리포트 출력, Diff, PoC 주입 등을 담당합니다.
- `supabase/migrations/`
  원격 프로젝트에 적용할 테이블 마이그레이션 파일이 들어갑니다.

## 요구 사항

- Node.js 18+
- npm
- Python 3.9+
- `mitmproxy`
- Supabase 프로젝트

## 빠른 시작

### 1. 의존성 설치

```bash
npm install
pip install -r proxy/requirements.txt
```

### 2. 환경변수 설정

```bash
cp .env.example .env
```

예시:

```env
VITE_API_BASE_URL=http://localhost:4000
VITE_SUPABASE_URL=https://<project-ref>.supabase.co
VITE_SUPABASE_ANON_KEY=<publishable-or-anon-key>
PORT=4000
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_SERVICE_ROLE_KEY=<service-role-key>
```

설명:

- `VITE_*`
  프런트에서 사용하는 값입니다.
- `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`
  서버에서 HAR 분석 결과를 Supabase에 저장할 때 사용합니다.

## 실행 방법

### 1. 프록시 실행

```bash
mitmdump -s proxy/modify_request.py
```

프록시 기본 주소:

- Host: `127.0.0.1`
- Port: `8080`

HTTPS를 보려면 `mitmproxy` 인증서를 대상 클라이언트/브라우저에 설치해야 합니다.

### 2. 분석 서버 실행

```bash
npm run server
```

기본 주소:

- `http://127.0.0.1:4000`

### 3. 프런트 실행

```bash
npm run dev
```

기본 주소:

- `http://localhost:5173`

## 일반적인 사용 흐름

### 실시간 캡처

1. 브라우저 또는 테스트 클라이언트의 프록시를 `127.0.0.1:8080`으로 설정합니다.
2. 프런트에서 분석 대상 URL을 입력합니다.
3. 필요하면 추가 제외 패턴을 입력합니다.
4. `캡처 시작`을 누릅니다.
5. 요청/응답 목록을 보면서 finding과 Diff를 확인합니다.

참고:

- 이미지 요청은 기본적으로 항상 제외됩니다.
- `Excluded` 입력칸은 추가 제외 규칙만 받습니다.

### 리플레이

1. 요청 카드를 클릭합니다.
2. Replay 모달에서 URL, 헤더, 바디를 수정합니다.
3. `요청` 버튼으로 다시 보냅니다.

보안 finding이 있는 경우:

- `PoC를 Replay에 주입` 버튼으로 재현 템플릿을 바로 모달에 넣을 수 있습니다.

### HAR 분석

HAR 업로드는 서버가 파일을 읽어 아래 항목을 계산합니다.

- 총 요청 수
- 평균 대기 시간
- 가장 느린 요청
- 메서드 분포
- 상위 호스트
- 상태코드 분포
- 콘텐츠 타입 분포
- 실패 요청 목록

분석 자체는 Supabase 없이도 가능하지만, 결과를 DB에 저장하려면 Supabase 서버 키가 필요합니다.

## Supabase 연동

### 저장 대상 테이블

이 프로젝트는 아래 테이블에 HAR 분석 결과를 저장합니다.

```sql
create table if not exists public.capture_har_analyses (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  file_name text not null,
  file_size bigint not null,
  total_entries integer not null,
  average_wait_ms numeric not null,
  slowest_url text,
  methods jsonb not null,
  top_hosts jsonb not null,
  status_codes jsonb not null default '{}'::jsonb,
  content_types jsonb not null default '[]'::jsonb,
  failed_requests jsonb not null default '[]'::jsonb
);
```

### 키 확인 위치

- `VITE_SUPABASE_URL`
- `VITE_SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`

위 값은 Supabase Dashboard의 `Settings > API`에서 확인할 수 있습니다.

주의:

- `SUPABASE_SERVICE_ROLE_KEY`는 서버 전용입니다.
- 프런트 코드에 직접 노출하면 안 됩니다.

### 현재 워크스페이스 상태

이 저장소에는 Supabase 마이그레이션 파일이 포함되어 있습니다.

- [supabase/migrations/20260417230435_create_capture_har_analyses.sql](/Users/mac/Tools/HttpViewer/supabase/migrations/20260417230435_create_capture_har_analyses.sql)

원격 프로젝트에 이미 다른 migration history가 있다면, `supabase db push` 전에 기존 이력과 로컬 이력을 맞춰야 할 수 있습니다. 그런 경우엔 SQL Editor에서 테이블을 직접 생성하는 방식이 더 안전할 수 있습니다.

## 리포트 출력

상단 `Export` 메뉴에서 다음 포맷을 출력할 수 있습니다.

- HTML
- JSON
- Markdown
- CSV

리포트에는 다음 정보가 포함됩니다.

- 요청/응답 목록
- 보안 finding
- OWASP 요약
- 엔드포인트 위험도 요약

`Mask Secrets`가 켜져 있으면 민감정보는 마스킹된 상태로 출력됩니다.

## UI 보조 기능

### Mask Secrets

민감값을 기본 마스킹합니다.

예:

- `Authorization`
- `Cookie`
- `Set-Cookie`
- 토큰/JWT/API Key
- Private Key 형식 문자열

### 오탐 처리(Suppress)

finding마다 다음 범위로 억제할 수 있습니다.

- 세션 오탐
- 엔드포인트 오탐
- 호스트 오탐
- 전역 오탐

### Diff

같은 엔드포인트의 이전 요청과 현재 요청을 비교합니다.

- 상태코드
- 바뀐 요청 헤더
- 바뀐 응답 헤더
- 요청 바디
- 응답 바디

기본 상태는 접힘입니다.

### Endpoint Priority

finding이 많이 몰린 엔드포인트를 우선순위로 정리합니다.

- 누적 점수
- finding 개수
- 최고 심각도
- 자주 걸린 OWASP 카테고리

기본 상태는 접힘입니다.

## 개발 팁

### 빌드 확인

```bash
npm run build
```

### 서버만 실행

```bash
npm run server
```

### 프런트만 실행

```bash
npm run dev
```

## 주의 사항

- 이 도구의 finding은 확정 취약점이 아니라 패턴 기반 탐지입니다.
- 실제 취약 여부는 재현 테스트와 서버 코드/인프라 설정 검토로 확인해야 합니다.
- `service_role` 키는 절대 브라우저나 공개 저장소에 노출하면 안 됩니다.
- 기존 Supabase 프로젝트에 migration history가 있는 경우, 무리하게 `repair`를 실행하기 전에 영향 범위를 먼저 검토하는 편이 안전합니다.

## 앞으로 확장하기 좋은 방향

- finding 결과의 프로젝트별 저장/조회 화면
- replay 결과 자동 비교
- finding별 코멘트 및 triage 상태
- 팀 공유용 보고서 템플릿
- 특정 finding 발생 시 Slack/이메일 알림
