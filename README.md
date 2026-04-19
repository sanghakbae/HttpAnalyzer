# HTTP Analyzer

`HTTP Analyzer`는 브라우저/클라이언트에서 발생한 HTTP 트래픽을 캡처하고, 요청/응답을 눈으로 확인하면서 보안 관점에서 빠르게 분류할 수 있도록 만든 로컬 분석 도구입니다.

이 프로젝트는 세 가지 축으로 구성됩니다.

- `mitmproxy`로 실시간 트래픽을 가로채고 수정/관찰
- `Node + Express` 서버로 캡처 상태, HAR 분석, 리플레이, Supabase 저장 처리
- `React + Vite` 프런트엔드로 요청/응답 확인, 보안 패턴 분석, 리포트 출력

## 핵심 기능

- 구글 로그인 기반 접근 제어
- 사이드 메뉴 기반 기능 분리(`Overview`, `Capture`, `Findings`, `HAR`, `Recent Data`)
- 실시간 HTTP 요청/응답 캡처
- 요청/응답 헤더 및 바디 확인
- 특정 요청 재전송(Replay)
- 캡처 흐름 기반 Mermaid 다이어그램 생성
- HAR 파일 업로드 및 성능/호스트/상태코드 분석
- 보안 패턴 탐지 및 `OWASP Top 10` 기준 요약
- 엔드포인트 우선순위 정리
- `Before / After` 비교용 Diff
- `HTML / PDF / JSON / Markdown / CSV` 리포트 출력
- HAR 분석 결과, 실시간 캡처 이벤트, 점검 이력을 Supabase에 저장
- 서버 저장 실패 시 `Recent Data` 로컬 fallback 저장
- 로컬 fallback 항목의 자동 재업로드 큐

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
├─ samples/
│  ├─ sample.har
│  ├─ sample-errors.har
│  ├─ sample-security.har
│  └─ sample-large.har
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
  프론트 API 서버입니다. 캡처 상태 조회, 리플레이, HAR 분석, 캡처 이벤트 저장, 점검 이력 저장을 처리합니다.
- `src/App.jsx`
  메인 UI입니다. 로그인, 사이드 메뉴, 실시간 요청 목록, 보안 finding, 리포트 출력, Diff, PoC 주입, 최근 이력 화면 등을 담당합니다.
- `supabase/migrations/`
  원격 프로젝트에 적용할 테이블 마이그레이션 파일이 들어갑니다.
- `samples/`
  HAR 업로드 테스트용 샘플 파일입니다.

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
VITE_API_BASE_URL=https://http-analyzer-api.onrender.com
VITE_SUPABASE_URL=https://<project-ref>.supabase.co
VITE_SUPABASE_ANON_KEY=<publishable-or-anon-key>
PORT=4000
HOST=127.0.0.1
DISABLE_CAPTURE=false
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_SERVICE_ROLE_KEY=<service-role-key>
```

로컬에서 프런트와 백엔드를 같이 실행할 때는 `VITE_API_BASE_URL=http://localhost:4000`으로 바꿔도 됩니다.

설명:

- `VITE_*`
  프런트에서 사용하는 값입니다.
- `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`
  서버에서 HAR 분석 결과를 Supabase에 저장할 때 사용합니다.
- `HOST`
  로컬은 보통 `127.0.0.1`, Render 같은 배포 환경은 `0.0.0.0`을 사용합니다.
- `DISABLE_CAPTURE`
  배포 백엔드에서 Playwright 캡처 API를 막고 저장/조회 API만 운영하려면 `true`로 둡니다.

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

### 로그인

1. 프런트 접속 후 구글 로그인 버튼을 누릅니다.
2. 현재 허용된 계정으로 로그인해야 메인 화면에 들어갈 수 있습니다.

현재 허용 계정:

- `totoriverce@gmail.com`

참고:

- 로그인 정보는 브라우저 `localStorage`에 저장됩니다.
- 이름 표시가 깨졌다면 로그아웃 후 다시 로그인하면 최신 디코딩 값으로 갱신됩니다.

### 실시간 캡처

1. 브라우저 또는 테스트 클라이언트의 프록시를 `127.0.0.1:8080`으로 설정합니다.
2. `Capture` 화면에서 분석 대상 URL을 입력합니다.
3. 필요하면 추가 제외 패턴을 입력합니다.
4. `캡처 시작`을 누릅니다.
5. 요청/응답 목록을 보면서 finding과 Diff를 확인합니다.
6. 캡처를 종료하면 세션 요약이 점검 이력으로 저장됩니다.

참고:

- 이미지 요청은 기본적으로 항상 제외됩니다.
- `Excluded` 입력칸은 추가 제외 규칙만 받습니다.
- `Capture` 화면에서는 요청별 보안 finding 요약만 보여주고, 상세 내용은 `Findings` 메뉴에서 확인합니다.
- `Findings에서 보기`를 누르면 해당 요청의 finding만 필터되어 바로 이동합니다.
- 종료 과정에서 발생한 `net::ERR_ABORTED`는 종료성 노이즈로 간주해 UI와 Recent Data에서 숨깁니다.

### 리플레이

1. 요청 카드를 클릭합니다.
2. Replay 모달에서 URL, 헤더, 바디를 수정합니다.
3. `요청` 버튼으로 다시 보냅니다.

보안 finding이 있는 경우:

- `PoC를 Replay에 주입` 버튼으로 재현 템플릿을 바로 모달에 넣을 수 있습니다.
- 긴 응답은 모달 내부에서 스크롤됩니다.

### Mermaid 생성

`Capture` 화면의 `Generate Mermaid` 버튼으로 현재 캡처된 요청을 기반으로 Mermaid 흐름도를 만들 수 있습니다.

- 결과는 본문이 아니라 전용 팝업으로 표시됩니다.
- 팝업 우측 상단 `복사` 버튼으로 Mermaid 코드를 바로 복사할 수 있습니다.
- 복사 후 팝업은 자동으로 닫힙니다.

### HAR 분석

`HAR` 화면에서 파일을 선택해 업로드할 수 있습니다. 서버는 아래 항목을 계산합니다.

- 총 요청 수
- 평균 대기 시간
- 가장 느린 요청
- 메서드 분포
- 상위 호스트
- 상태코드 분포
- 콘텐츠 타입 분포
- 실패 요청 목록

분석 자체는 Supabase 없이도 가능하지만, 결과를 DB에 저장하려면 Supabase 서버 키가 필요합니다.

### Recent Data

`Recent Data` 화면에서는 아래 내용을 확인할 수 있습니다.

- 최근 점검 이력
- 최근 캡처 이벤트
- 최근 7일 / 30일 기준 통계 대시보드
- 점검 이력 상세 모달
- 점검 이력별 `HTML / PDF` 리포트 재다운로드
- 항목별 저장 출처(`DB`, `로컬`, `로컬(대기)`)

중요:

- DB 저장이 실패해도 `Recent Data`에는 로컬 fallback으로 즉시 표시됩니다.
- `로컬(대기)`는 아직 DB 동기화가 안 된 항목입니다.
- 앱이 다시 열리거나 주기 동기화가 돌 때 서버가 정상이면 자동으로 재업로드를 시도합니다.
- 재업로드가 성공하면 로컬 대기 항목은 제거되고 DB 이력만 남습니다.

## Supabase 연동

### 저장 대상 테이블

이 프로젝트는 아래 테이블을 사용합니다.

#### 1. HAR 분석 결과

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

#### 2. 실시간 캡처 이벤트

```sql
create table if not exists public.capture_http_events (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  capture_session_id uuid,
  target_url text,
  request_timestamp timestamptz,
  request_method text,
  request_url text,
  request_resource_type text,
  request_headers jsonb not null default '{}'::jsonb,
  request_body text not null default '',
  response_timestamp timestamptz,
  response_url text,
  response_status integer,
  response_status_text text,
  response_headers jsonb not null default '{}'::jsonb,
  response_body_preview text not null default '',
  error_text text
);
```

#### 3. 점검 이력

```sql
create table if not exists public.capture_inspection_runs (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  capture_session_id uuid,
  target_url text not null,
  started_at timestamptz,
  ended_at timestamptz not null default now(),
  total_exchanges integer not null default 0,
  total_errors integer not null default 0,
  total_findings integer not null default 0,
  critical_findings integer not null default 0,
  high_findings integer not null default 0,
  security_only boolean not null default false,
  mask_sensitive boolean not null default true,
  excluded_patterns jsonb not null default '[]'::jsonb,
  owasp_summary jsonb not null default '[]'::jsonb,
  endpoint_summary jsonb not null default '[]'::jsonb,
  report_snapshot jsonb not null default '{}'::jsonb
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

## GitHub Actions + Render 배포

이 저장소는 프런트와 백엔드를 분리해서 배포하도록 구성되어 있습니다.

- 프런트: GitHub Pages
- 백엔드: Render Web Service
- DB: Supabase

### GitHub Actions 설정

GitHub 저장소 `Settings > Secrets and variables > Actions`에 아래 값을 등록합니다.

프런트 API URL은 저장소 변수(`Variables`)로 등록합니다. 값을 등록하지 않으면 GitHub Actions는 기본값으로 `https://http-analyzer-api.onrender.com`을 사용합니다.

```text
VITE_API_BASE_URL=https://http-analyzer-api.onrender.com
```

프런트 빌드용 Supabase 값은 시크릿(`Secrets`)으로 등록합니다.

```text
VITE_SUPABASE_URL=https://<project-ref>.supabase.co
VITE_SUPABASE_ANON_KEY=<publishable-or-anon-key>
```

Render 자동 배포 트리거용:

```text
RENDER_DEPLOY_HOOK_URL=<render-deploy-hook-url>
```

`RENDER_DEPLOY_HOOK_URL`은 Render 서비스의 `Settings > Deploy Hook`에서 생성한 URL입니다. 이 값이 없으면 프런트 배포만 진행되고 백엔드 배포 트리거 단계는 건너뜁니다.

### Render 환경변수

Render Web Service에는 아래 값을 등록합니다.

```text
NODE_ENV=production
HOST=0.0.0.0
DISABLE_CAPTURE=true
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=true
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_SERVICE_ROLE_KEY=<service-role-key>
```

현재 권장 운영 방식은 배포 백엔드를 저장/조회 API로만 쓰는 것입니다.

- 동작: `/api/health`, `/api/recent-analyses`, `/api/inspection-runs`, `/api/capture-events/batch`, `/api/analyze-har`
- 비활성화: `/api/capture/start`

실제 브라우저 캡처와 Replay는 로컬 앱에서 사용하는 것을 권장합니다.

### Render Blueprint

`render.yaml`이 포함되어 있으므로 Render에서 Blueprint로 연결할 수 있습니다.

- Service Name: `http-analyzer-api`
- Build Command: `npm ci`
- Start Command: `npm run start`
- Health Check Path: `/api/health`
- 예상 백엔드 URL: `https://http-analyzer-api.onrender.com`

Render에서 서비스 이름이 이미 사용 중이면 실제 생성된 URL을 GitHub Actions 변수 `VITE_API_BASE_URL`에 다시 등록해야 합니다.

### 배포 사이트 동작

배포 사이트에서도 기존 메뉴는 그대로 표시됩니다.

- `Overview`, `Capture`, `Findings`, `HAR`, `Recent Data` 메뉴 표시
- `HAR` 업로드, `Replay`, 리포트 출력은 백엔드 API URL을 통해 실행
- Render 환경에서 `DISABLE_CAPTURE=true`로 둔 경우 실시간 브라우저 캡처 시작만 서버에서 차단
- 실제 브라우저 창을 띄워 세션을 이어가는 캡처는 로컬 앱에서 실행하는 것을 권장

### 현재 워크스페이스 상태

이 저장소에는 Supabase 마이그레이션 파일이 포함되어 있습니다.

- [supabase/migrations/20260417230435_create_capture_har_analyses.sql](/Users/mac/Tools/HttpViewer/supabase/migrations/20260417230435_create_capture_har_analyses.sql)
- [supabase/migrations/20260417233000_create_capture_http_events.sql](/Users/mac/Tools/HttpViewer/supabase/migrations/20260417233000_create_capture_http_events.sql)
- [supabase/migrations/20260417235500_create_capture_inspection_runs.sql](/Users/mac/Tools/HttpViewer/supabase/migrations/20260417235500_create_capture_inspection_runs.sql)

원격 프로젝트에 이미 다른 migration history가 있다면, `supabase db push` 전에 기존 이력과 로컬 이력을 맞춰야 할 수 있습니다. 그런 경우엔 SQL Editor에서 테이블을 직접 생성하는 방식이 더 안전할 수 있습니다.

점검 이력 테이블에 `report_snapshot` 컬럼이 없다면 아래 SQL을 추가로 실행하면 됩니다.

```sql
alter table public.capture_inspection_runs
add column if not exists report_snapshot jsonb not null default '{}'::jsonb;
```

## 리포트 출력

상단 `Export` 메뉴에서 다음 포맷을 출력할 수 있습니다.

- HTML
- PDF
- JSON
- Markdown
- CSV

리포트에는 다음 정보가 포함됩니다.

- 표지
- 점검자
- 점검 일시
- 결론
- 요청/응답 목록
- 보안 finding
- OWASP 요약
- 엔드포인트 위험도 요약

`Mask Secrets`가 켜져 있으면 민감정보는 마스킹된 상태로 출력됩니다.

## 샘플 HAR 파일

테스트용 HAR 파일은 [samples](/Users/mac/Tools/HttpViewer/samples)에 들어 있습니다.

- [samples/sample.har](/Users/mac/Tools/HttpViewer/samples/sample.har)
  기본 업로드/저장 동작 확인용
- [samples/sample-errors.har](/Users/mac/Tools/HttpViewer/samples/sample-errors.har)
  오류 응답과 실패 요청 확인용
- [samples/sample-security.har](/Users/mac/Tools/HttpViewer/samples/sample-security.har)
  보안 패턴 탐지 확인용
- [samples/sample-large.har](/Users/mac/Tools/HttpViewer/samples/sample-large.har)
  대량 요청 흐름 확인용
- [samples/sample-vulnerable.har](/Users/mac/Tools/HttpViewer/samples/sample-vulnerable.har)
  민감정보 노출, 보안 헤더 누락, 주입 흔적 등 취약 징후 테스트용

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

### Recent Data 저장 정책

최근 점검 이력과 캡처 이벤트는 두 단계로 관리합니다.

- 1차: 로컬 브라우저 저장
- 2차: Supabase 저장

저장 실패 시에도 사용자는 `Recent Data`에서 바로 이력을 볼 수 있어야 하므로, 캡처 종료 시점에 먼저 로컬 fallback을 기록합니다. 이후 백엔드가 정상 응답하면 자동 재업로드 큐가 DB 저장을 다시 시도합니다.

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
