# HTTP Analyzer

`mitmproxy`로 특정 HTTP 요청/응답을 가로채고, `React + Vite` 프런트엔드에서 HAR 파일을 업로드해 분석하는 예제 프로젝트입니다.

## 구성

- `proxy/modify_request.py`: `proxy/rules.json` 규칙을 읽어 요청 바디 수정 및 응답 출력
- `server/index.js`: HAR 업로드/분석 API, 프록시 규칙 저장, Supabase 저장
- `src/App.jsx`: Google OAuth 로그인, HAR 업로드, 규칙 관리 UI

## 1. mitmproxy 실행

Python 가상환경 생성 후:

```bash
pip install -r proxy/requirements.txt
mitmdump -s proxy/modify_request.py
```

현재 로컬 환경이 Python 3.9라면 `mitmproxy 9.x` 기준으로 설치됩니다.

프록시를 거쳐 들어온 요청은 `proxy/rules.json`과 비교됩니다. 예시 기본 규칙은 `example.com/api` 요청에 대해:

- 요청 바디에 `intercepted: true`
- 요청 바디에 `source: "mitmproxy-addon"`
- `message` 필드가 있으면 문자열 뒤에 `[modified]`

값을 추가/수정한 뒤 서버로 전달합니다.

응답 본문은 `mitmdump` 실행 터미널에 출력됩니다.

## 2. React + Vite 프런트엔드

```bash
npm install
npm run dev
```

기본 개발 서버는 `http://localhost:5173` 입니다.

Google OAuth를 쓰려면 Supabase 대시보드에서:

- Authentication > Providers > Google 활성화
- Redirect URL에 `http://localhost:5173` 추가
- `.env`에 `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY` 설정

## 3. HAR 분석 서버

```bash
cp .env.example .env
npm run server
```

기본 API 서버는 `http://localhost:4000` 입니다. 이 서버는 프런트엔드에서 편집한 프록시 규칙을 `proxy/rules.json`으로 저장합니다.

## 4. Supabase 테이블 예시

`har_analyses` 테이블 예시:

```sql
create table public.har_analyses (
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

## 5. 프록시 설정

브라우저 또는 테스트 클라이언트에서 mitmproxy 프록시 주소를 지정해야 합니다.

- Host: `127.0.0.1`
- Port: `8080`

HTTPS 트래픽을 복호화하려면 mitmproxy 인증서를 클라이언트에 설치해야 합니다.
