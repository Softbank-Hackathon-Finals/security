# ADR-0018: 자격 전달 전에 DB 경로와 TLS 설정 검증

- 상태: 구현·단위 검증, 실제 PG18.4/서비스 CI 검증 중.
- 요구: CTRL-01·02, SEC-PATCH-08, identity-boundary, network-tls.
- 플랫폼 기준: `bb174860bedf100de3970c3e8e410f02f23994e2`.

## 발견

기존 서비스는 `psycopg.connect` 뒤 실제 TLS 여부를 검사했다. 따라서 잘못된 mounted DSN의
`sslmode=disable/prefer`도 먼저 DB 클라이언트로 전달될 수 있었다. `host=/socket,network-host`와 같은
혼합 host 목록은 문자열의 첫 `/`만으로 private socket 경로로 오해할 여지도 있었다.
이는 보호된 운영 설정을 잘못 구성했을 때의 문제이며 외부 API 입력으로 DSN을 바꿀 수 있다는 뜻은 아니다.

DB 클라이언트를 감시하는 네트워크 없는 시험에서 세 경우 모두 **수정 전 3 FAIL**로 재현했다.
실제 외부 서버에 접속하거나 자격을 전송하지 않았다.

## 결정

`review_connection_parameters`가 libpq의 정식 parser로 DSN을 읽고 **연결 전에** 다음을 요구한다.

- 하나의 명시적인 host·port·DB·reader. host/port 목록, 암묵적 기본 대상, service profile은 거부한다.
- private Unix socket은 하나의 절대 디렉터리이며 hostaddr 재지정과 상위 경로 이동을 허용하지 않는다.
- TCP는 `sslmode=verify-full`과 명시적인 절대 CA mount를 요구한다. 선택 hostaddr는 숫자 IP 하나다.
- PGSERVICE/PGSERVICEFILE과 등록되지 않은 PGHOSTADDR 환경 우회를 거부한다.
- GSS 암호화가 TLS보다 우선할 수 있어 `gssencmode=disable`을 명시한다. 기존 접속/문장 기한,
  read-only transaction, pg_catalog search_path를 강제한다.

검증한 parameter를 연결에 넘기며, 연결 후의 실제 host/TLS 확인도 유지한다. 불일치 연결은 닫는다.
mounted DSN은 매 요청 다시 읽어 기존 비밀 관리 경로의 자격 회전을 반영한다. 완전한 DSN/암호를
오류에 넣지 않는다. 새 발급기, 비밀 저장소 또는 네트워크 탐색 기능은 추가하지 않는다.

예시 형식(자격은 보호된 DSN mount로 공급):

```text
host=registered-db-service port=5432 dbname=platform user=security_reader sslmode=verify-full sslrootcert=/run/database/ca.crt
```

기존 CNPG의 단일 등록 Service 주소와 호환된다. multi-host DSN이나 service profile에 의존한 배포는
명시적인 단일 경로로 인수해야 한다. pooler의 실제 대상 DB 신원과 HBA 설치까지 이 검사가 증명하지는 않는다.

## 검증

관련 Windows 단위 **32 PASS / 1 SKIP, 2.28초**. skip은 POSIX symlink/FIFO 시험이다.
새 시험은 연결 전 거부, 환경 우회, 자격 회전, 강제 옵션, 연결 후 불일치 종료를 확인한다.
PG18.4 실제 TLS/HBA 시험의 허용 연결도 이 parameter 경로를 사용하도록 연결했다.
기존 실제 서비스 프로세스/컨테이너·T10/Sova 소비의 회귀는 CI에서 수행한다.

근거: [libpq 연결·환경 기본값·host/hostaddr·SSL/GSS](https://www.postgresql.org/docs/18/libpq-connect.html),
[Psycopg 정식 conninfo parser](https://www.psycopg.org/psycopg3/docs/api/conninfo.html).
