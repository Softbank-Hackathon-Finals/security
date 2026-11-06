# 보안 서비스 개발 기록

## 2026-11-06 시작

- 사용자 범위: security/sova-test의 개인 환경 구현·검증·기능별 커밋·푸시.
- 기존 기반: security `3093814`, sova-test `7d79d65`, 패키지 0.10.0.
- 작업 브랜치: 두 저장소 `feature/security-service-integration`.
- platform 기준: `f602b39a949b99f3e2e7be901103063e78a52a70` (읽기 전용 확인).
- 두 원문: `docs/proposals/manifest.json`의 바이트 지문 유지.
- 설계: [ADR-0001](../adr/0001-security-review-service.md).
- 계획: 등록 context/전송 계약 → 인증·판정 서비스 → HTTPS 소비/병행 판정 →
  Sova 실행 연결 → 실제 TLS/DB/프로세스 실패 시험 → 패키징·인계.
- 미검증: 실제 T7 서비스 audience·운영 권한 등록, 플랫폼 실행 집행 연결, 클라우드 인수.
- 시각/상태: 구현 시작. 기존 테스트 통과 수를 새 서비스 검증으로 사용하지 않는다.

## 기록 원칙

각 변경은 요구사항 ID, 기준 SHA, 선택 이유, 코드, 시험 명령/결과, 증거 위치와
미검증 사항을 기록한다. 설계/구현/모의 검증/실환경 검증을 구분한다. 실패 실험과
포기한 대안도 다음 판단에 필요한 근거를 남긴다. 비밀 원문·개인/운영 식별자는 기록하지 않는다.

## SVC-01: 등록·인증·판정 전송 계약

- 요구: SEC-PATCH-05·10, CTRL-01·02·07, POL-01·03·09·11, SG-1·2.
- 기준 SHA: 위 f602b39 전체 값. 기존 정책/증거/승인 계약을 재사용한다.
- 구현: `domain/review_service.py`, `application/review_service.py`,
  `adapters/{review_identity,review_https,remote_review}.py`, `interfaces/review_asgi.py`,
  `application/shadow_review.py`, codec의 등록/요청/응답 kind 세 개.
- 설계 이유: caller 제공 정책/증거를 받지 않고 현재 등록만 조회한다. 온라인 TokenReview,
  고정 audience/SA UID/tenant/scope, 전후 재인증, nonce/context 결속, 최대 5초 기한을 유지한다.
  shadow와 enforce를 분리하고 결과에 실행 권한을 부여하지 않는다.
- 검증: 관련 단위 시험 73 PASS, 실제 로컬 uvicorn TLS 시험 9 PASS.
  잘못된 CA/hostname, redirect, 응답 한도/형식, 철회, 서비스 중단을 검사했다.
- 실패와 수정: Windows localhost의 IPv6/DNS 경로 때문에 2초 기한을 넘던 TLS fixture는
  올바른 IP SAN을 가진 loopback IPv4로 고쳤다. 운영 TLS 검증/기한을 완화하지 않았다.
  HTTP body 수신과 worker의 기한을 합산하도록 수정했고, 만료 worker는 슬롯을 계속 점유한다.
  의도한 30ms 장애 시험 이후 정상 복구 확인은 별도 1초 기한을 사용해 OS 스케줄링 의존을 제거했다.
- 증거: `tests/unit/test_review_{service,identity,asgi}.py`, `tests/integration/test_review_tls.py`.
  로컬 실행 로그는 `.local-notes/service-work/`에 보관하고 비밀/개인 실행 상태는 커밋하지 않는다.
- 상태: 구현 + 로컬 TLS 실측 + 합성 권한/측정 시험. 실제 K8s TokenReview/T7 audience는 미검증.

## SVC-02: 읽기 전용 저장소와 테넌트 고정

- 요구: CTRL-01·02·04, POL-01, SEC-PATCH-10. 기준 SHA 동일.
- 구현: `adapters/{postgres_review,review_mounts,review_database}.py`, `interfaces/review_server.py`.
- 선택: 기존 SQL 7개/저장소를 그대로 사용한다. API 등록/쓰기 권한은 제공하지 않는다.
  GUC 기반 RLS의 한계를 발견하여 [ADR-0002](../adr/0002-tenant-fixed-service-reader.md)를 추가했다.
  별도 역할의 restrictive 고정 tenant 정책과 SELECT만 허용하고 매 연결 정책/권한 drift를 검사한다.
- 검증: PostgreSQL 17.11 실제 isolated cluster에서 등록/프로그램 철회·hold·타 tenant 거부,
  INSERT/DELETE 거부, 직접 SQL tenant 전환, 정책 삭제/변경·쓰기 grant·membership 차단.
  실제 TLS + Ed25519 서명 토큰 검증기 **모형** + PostgreSQL 연쇄 시험 여섯 종류 통과.
- 전체 회귀 중간 결과: security 752 PASS(40.12초), Sova 직전 1,102 PASS/3 SKIP.
  이후 독립 프로세스/배포 명세 추가는 별도로 검증한다. 이 수치를 최종 산출물 수치로 재사용하지 않는다.
- 실패와 수정: mount를 검사하기 전 FIFO open이 대기할 수 있어 NONBLOCK open 후 fstat로 수정.
  Windows 기본 Python에는 jsonschema/psycopg가 없었다. 인터롭은 준비된 `.venv`/Linux 환경으로
  수행했으며 의존성 누락 실패를 제품 오류나 통과로 집계하지 않았다.
- 상태: 로컬 PostgreSQL·TLS 실측. CNPG/OpenBao 운영 역할, 감사 PVC/T24 전달, 클라우드 IAM은 미검증.

## SVC-03: 호스트 실행·플랫폼 계약 연결

- 요구: SEC-PATCH-05·06·08, POL-06·07·09·11, SG-2·3. 기준 SHA 동일.
- 구현: security `adapters/platform_review.py`; Sova `security/application/remote_program.py`.
- 플랫폼: 원래 `PlanGateSession.fingerprint`와 plan digest를 사용한다. `profile_version="1"`,
  `initial/post_apply`, application_id를 보존한다. 실제 `T10GateAuthority` 전후 검사를 호출하며
  동일 transaction에 전달하는 `load_registration`을 추가해 host plan lock 책임을 명시했다.
  원격 호출을 잠금으로 간주하지 않는다. 승인 revision은 안정적인 context 지문만 결속한다.
- 검증: 고정 platform 소스의 실제 모듈/SQLite 승인·단일 dispatch·응답 유실 조정 15 PASS.
  측정값/신원 공급자는 합성이며 플랫폼 배포 인수와 구별한다.
  Sova 기존 SQLite effect/패치 실행 시험 31 PASS: 사전 실패 효과 0회, 사후 실패 APPLIED+hold,
  재시도해도 재적용 없음, shadow 비교가 실행하지 않음.
- 상태: 구현 + 소비 계약/로컬 원장 실측. 실제 platform 연결은 인계 대상이며 원본 저장소를 수정하지 않았다.

## SVC-04: 진행 중 플랫폼 변경의 별도 인수

- 새 기준: `b19488e2debbee8bbe120f1309eadbe19df85b6f`, 최초 f602b39보다 46개 커밋 진행.
  [비교](https://github.com/Softbank-Hackathon-Finals/platform/compare/f602b39a949b99f3e2e7be901103063e78a52a70...b19488e2debbee8bbe120f1309eadbe19df85b6f).
- T19 StoredGateServices는 같은 T10 GateRecordView transaction에 현재 서명/권한/예외/T13을
  연결한다. 이를 upstream으로 재사용하고 별도 T19 저장·발급 경로는 만들지 않는다.
- NET-01.2/01.3은 DB/pooler 원문 둘 다 필요하다. 새 네트워크 집계 검증을 약화하지 않는다.
- T14 앱 격리는 실제 로컬 PostgreSQL 검증이 추가됐지만 AWS 객체의 양쪽 실제 접근은 미검증이다.
  EKS 별도 namespace의 Deployment TCP 정책 집행 성공은 이전 DB/pooler FAIL을 뒤집지 않는다.
- 수정: `PLATFORM_BASELINES`, 명시적 `baseline_sha`, 양쪽 source checkout/CI 소비 시험.
- 시험: 새 기준 실제 모듈/SQLite 15 PASS(6.17초). 기존 기준도 별도 유지한다.
- 원본 platform 폴더: 계속 `505d451`에서 수정 없음. 참조 checkout은 security의 무시된 개인 폴더에만 둔다.
- 상태: 계약 소비 검증. 플랫폼 개발이 계속되므로 이후 head의 자동 호환은 주장하지 않는다.

## SVC-05: 독립 실행·배포 준비·사고 관점 보강

- 요구: CTRL-01·02·06·07, SEC-PATCH-09·10, POL-01·03·10. 현재 기준 b19488e.
- 독립 프로세스: 실제 Python 서비스 프로세스 + TLS + 온라인 Ed25519 검증기 모형 +
  테넌트 고정 PG 역할의 연결/철회 포함 6 PASS(7.57초). 실제 Kubernetes 인증으로 확대하지 않는다.
- 배포 생성기: 명시한 digest·tenant·audience·주소/port로 JSON만 생성. non-root/read-only,
  최소 RBAC, SA 자동 mount 해제, NetworkPolicy와 제한 자원을 구성한다. apply는 하지 않는다.
- 사고 검토 중 원본 관측을 재수집할 때 heartbeat/finding 유효기간이 늘어날 수 있음을 발견했다.
  `team_detection.import_detection`의 만료를 원본 last_success/event 시각에도 결속했다.
  관련 단위 시험 31 PASS; 오래된 원본의 재수집으로 새 보안 근거를 만들지 않는다.
- 로컬 감사 파일에 16MiB 기본 상한을 추가했다. 가득 차면 기존 기록을 보존하며 신규 판정을 보류한다.
  이것은 감사 보관 정책/전체 PVC 용량 관리의 대체물이 아니다.

## SVC-06: 전체 증거 경로와 회귀 검증

- 요구: SEC-PATCH-05·10, CTRL-02·07, POL-03·09·11. 기준 b19488e/f602b39.
- 정상 서명 원본을 모두 채운 실행 시험에서 5초 기한 초과를 발견했다. 연결만 요청별로
  재사용하고 현재 원본을 묶음 검증하도록 수정했다. 공통 인증 callback의 tuple 반환 거부도
  실제 서비스 시험에서 발견·수정했다. [ADR-0003](../adr/0003-request-scoped-live-evidence.md)에
  설계와 실패 기록을 남겼다. callback 계약이나 만료·철회 검사는 완화하지 않았다.
- 코드: `review_connections`, `program_evidence`, `registered_program`, `security_program`,
  `review_service`, `review_server`. 실제 TLS/PG 서비스 7 PASS(10.44초).
- 전체 Linux PostgreSQL 17.11·OPA 1.22 회귀: security **775 PASS, 43.03초**;
  Sova **1,102 PASS, 3 SKIP, 107.56초**. 격리 DB를 만들고 시험 뒤 종료했다.
  Sova skip은 실제 컨테이너/Collector/등록된 AWS SQS 시험이다. 합성 클라우드 검증으로 세지 않는다.
- 증거: `tests/integration/test_review_host_runtime.py`, 단위 회귀, 개인 실행 로그
  `.local-notes/service-work/{security,sova-test}-pg-opa-tests.txt`.
- 배포 생성기 등 Windows 관련 시험: 46 PASS/1 POSIX 전용 SKIP. Linux 전체에는 해당 시험 포함.
- 현재 Docker 엔진 두 로컬 endpoint가 실행 중이지 않음을 확인했다. Kubernetes 명세 생성 시험은
  통과했지만 컨테이너 이미지 실행이나 실제 CNI/RBAC 차단의 증거로 사용하지 않는다.
- [22개 검사 대응표](../platform-control-traceability.md)를 추가했다. 6개 범주/하위 시험과
  추가 요구를 분리하고 부분적인 T14/T19 PASS를 전체 프로그램 인수로 확대하지 않는다.
- 상태: 로컬 실제 DB/TLS + 모의 권한/측정 검증. 운영 TokenReview·CNI·T24 인수는 남아 있다.

## SVC-07: 원격 CI의 엄격한 TLS 검증

- 최초 push `b3cbbe6`의 두 platform-contract 작업과 secrets 작업은 통과했다.
  Python 3.14 package에서 TLS 시험 8개가 실패했고 3.11 작업은 matrix fail-fast로 취소됐다.
- 원인: 시험용 인증서에 Authority Key Identifier와 엄격한 CA key usage가 없었다.
  Python 3.12에서 VERIFY_X509_STRICT를 켜 `Missing Authority Key Identifier`를 재현했다.
  [Python 공식 변경 설명](https://docs.python.org/3/library/ssl.html#ssl.create_default_context)에
  따르면 3.13부터 엄격한 검증이 기본이다.
- 수정: `tests/tls_review_support.py`의 일회용 CA/leaf를 올바른 X.509 확장으로 발급한다.
  생산 코드의 TLS 검증은 바꾸지 않는다. TLS wire 시험은 구버전 Python에서도 strict flag를 켠다.
- 상태: 로컬 TLS 회귀 후 원격 CI 재검증. 최초 실패는 통과로 집계하지 않는다.

### SVC-07 재검증 결과

`606623dd66bddbb64e8bfb0f96f62ab42dd92d96`의
[CI 실행](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42196071522)은
Python 3.11/3.14, 두 플랫폼 기준, secrets 모두 통과했다. Sova의
[고정 패키지 소비 CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42195818784)도 통과했다.
같은 security commit을 git archive한 별도 잠금 환경에서 wheel을 빌드·설치하고
Sova/bravo_gate 없이 import/CLI help와 pip check를 확인했다.
로컬 wheel SHA-256은 `86259bf30834cd0c7a41beb014db687d55b010efa71368d7fb4dbcd3006dc4ce`다.
이는 개인 빌드이며 정식 발행/서명된 릴리스가 아니다.

## SVC-08: 플랫폼부터 독립 보안 프로세스까지 연결

- 요구: SEC-PATCH-05·06·10, CTRL-01·02, POL-09·11. 기준 f602b39와 b19488e.
- 코드: `tests/platform_review_support.py`, `tests/review_runtime_support.py`,
  `tests/integration/test_platform_review_runtime.py`. 기존 fixture를 공유하도록 정리했다.
- 실제 T10/T19·SQLite 승인 → TLS 독립 프로세스 → SELECT-only PostgreSQL → 원본 Ed25519
  증거를 연결했다. T13/T14 측정과 TokenReview API, 외부 컷오버 실행기는 여전히 모형이다.
  시험 등록 행은 호스트의 동일 plan transaction에서 읽고 변경하는 시험 어댑터다.
  운영 플랫폼에 새 table을 설치한 것이 아니다.
- f602b39 연결 시험 10 PASS(58.65초), b19488e 연결+기존 실행 시험 17 PASS(63.05초).
  initial/post_apply 각각에서 승인 후 원본 issuer·서비스 등록·호스트 등록·workload 철회는
  외부 실행 0회이며 SHIFT를 유지했다. 정상 실행 후 응답 유실은 SAFE_HOLD와 POST 1회/GET 1회다.
- 최초 반복 실행은 같은 resource의 프로그램을 새 시각으로 재등록해서 anti-rebinding 검사가
  거부했다. 각 시험 resource ID를 분리했고 생산 코드의 보호를 바꾸지 않았다.
- GitHub CI의 격리 PostgreSQL socket과 Python 3.14의 고정 platform source를 연결해
  이 경로를 지속 시험한다. 클러스터/CNI/업무 데이터 인수 상태는 별개다.

## SVC-09: 실제 Kubernetes 인증·철회와 incident hold

- 요구: CTRL-01·02·04, POL-01·09·11, SG-1, SEC-PATCH-05. 기준 b19488e.
- 코드: `tests/kubernetes_api_support.py`, `test_kubernetes_review_identity.py`,
  `test_platform_review_runtime.py`, CI의 checksum 고정 envtest 설치.
- [ADR-0004](../adr/0004-local-kubernetes-authentication.md): 새 로컬 Kubernetes 1.35.0 API·etcd 3.6.6,
  실제 TokenRequest/TokenReview, 생성 명세의 RBAC만으로 시험한다. 기존 kubeconfig를 읽지 않는다.
- 단독 실제 API 5 PASS(23.96초). 실제 API와 T10/TLS/PG 묶음 17 PASS(107.00초).
  bound Secret 철회 10.023초, SA 철회 10.017초. JUnit 속성 2개에 관한 형식 경고는 이후
  속성 기록 실행에서 legacy JUnit을 명시했다. 인증/철회 실패를 경고로 무시한 것이 아니다.
- 이 전파 지연 때문에 다음 설계를 명확히 했다: 침해 시 기존 호스트 보류/승인 제한과 별도
  보안 hold를 먼저 적용하고 자격을 철회한다. 자동 hold 해제나 기존 앱 중단은 추가하지 않는다.
- 추가 실제 API/T10/PG 시험 2 PASS(11.88초). 삭제 직후 TokenReview가 두 번 모두 여전히
  성공했지만 current hold로 접수는 0.085/0.087초에 거부됐으며 외부 실행은 0회였다.
- 원격 `f98810c`의 [전체 서비스 체인 CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42197704724)는
  모든 작업 통과. 실제 API 추가분은 별도 commit/CI로 검증한다.
- 미검증: 팀 EKS/RKE2 배포판·CNI·Pod·실제 DB/Secret 연동, 운영 revocation 상한,
  host-side 보류 writer의 운영 배선, 이미 접수한 실행의 실환경 조정. 로컬 실측과 구분한다.

### SVC-09 CI 결과와 공개 checksum 오탐

- `051687a`의 Python 3.11/3.14 및 두 플랫폼 계약 작업은 통과했다.
  secrets 작업은 `tests/kubernetes_api_support.py:21`의 공개 kube-apiserver 바이너리
  SHA-256을 `generic-api-key`로 탐지했다. 토큰이나 키를 저장한 결과가 아니다.
- `.gitleaks.toml`에 해당 공개 digest의 정확한 값만 예외로 추가했다. 파일 전체,
  규칙 전체 또는 테스트 디렉터리를 제외하지 않는다. 전체 Git 이력을 다시 검사한다.
- 근거: 공식 SIG envtest v1.35.0 archive SHA-512 검증과 추출 바이너리 SHA-256 검증,
  CI run `42199949004`의 secrets 작업 및 마스킹된 로컬 이력 보고서.

## SVC-10: 세 번째 플랫폼 기준과 실제 T7 audience 경계

- 요구: CTRL-01·02, POL-01·09·11, SG-1, SEC-PATCH-05. 기준 `c225c86cf5e408b5fcd016b0e367d3672d1bac44`.
- `b19488e` 이후 10개 커밋은 console 초기 판정 표시·allowlist 기반 agent 관측·의존성 및
  설계 문서 변경이다. T10/T19 집행 코드의 변경은 없었다. 기준을 자동 추적하지 않고 세 SHA를
  명시하고 각 계약 CI를 유지한다. 사용자 platform 작업 사본은 변경하지 않았다.
- 전체 로컬 보안 시험: `SOVA_PLATFORM_SOURCE=<c225c86 checkout>`와 실제 PG/OPA/API를
  지정하여 **794 PASS, 153.31초**. 이후 추가한 T7/audience 시험은 **3 PASS, 4.47초**.
- 실제 T7 acquire는 API audience에서 성공하지만 보안 서비스가 해당 토큰을 거부한다.
  서비스 audience를 주면 T7의 최종 대상 SelfSubjectReview가 HTTP 401로 거부한다.
  [ADR-0005](../adr/0005-service-credential-audience.md)에 기존 Kubernetes projected token
  경로를 내부 소비자의 기본 방향으로 정했다. 새 issuer를 만들거나 두 audience를 합치지 않는다.
- 시험의 issuer 접근은 shim이며 Tailscale·kubelet 실환경 인수가 아니다. 외부 소비자를 위한
  T7 확장은 플랫폼 인계 사항으로 남긴다. 문서의 형식 호환 설명을 실제 동작에 맞춰 보완했다.
- `baba9ba` CI의 secrets 및 이전 두 계약/3.11은 통과했으나 3.14에서 서명 증거 전체 경로
  15개 시험이 실패했다(779 PASS). 로컬 통과로 덮지 않고 성능 계측을 이어간다. 공개 digest
  예외 추가는 서비스 동작을 바꾸지 않았다. 최종 원격 인수는 이 실패를 해결한 뒤 판정한다.

## SVC-11: 제한 시간 안의 현재 증거 검증

- 요구/설계/수정 코드는 [ADR-0006](../adr/0006-bounded-live-route-reads.md)에 기록했다.
  기준 c225c86, wire·DB schema 변경 없음. 고정 타입 정보만 재사용하고 현재 증거 경로를
  묶어서 조회한다. 5초 기한, 원본 서명, 조회 전후 철회·변경 검사는 유지한다.
- `5abc729` [원격 CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42202409928)는
  세 플랫폼 계약, Python 3.11/3.14, secrets 모두 통과했다. 이전 실패가 간헐적이라는 점과
  실제 반복 비용을 모두 기록하며 특정 CI 호스트 원인으로 단정하지 않는다.
- 같은 잠금 Python 3.14 계측에서 함수 호출 약 3,598만→1,122만, 계측 시간 9.618→2.967초.
  이는 프로파일러를 켠 수치다. 계측+PG 경계 묶음 32 PASS, 14.77초.
- `pytest tests/contracts/test_modernization_codec.py tests/unit/test_program_evidence.py -q`:
  64 PASS. 이후 실제 부모 철회 race 시험 3개를 추가했다.
- 잠금 Python 3.14 + c225c86 + 실제 PG/OPA/Kubernetes 전체: **826 PASS, 123.68초**.
  모의 공급자와 실제 인프라의 구분은 기존 SVC-08~10을 따른다. 원격 CI도 변경 커밋으로 재검증한다.

## SVC-12: 최소 입력의 서비스 이미지와 실제 컨테이너 검증

- 기준 c225c86. 요구·설계 이유·인수 경계는 [ADR-0007](../adr/0007-commit-bound-service-image.md).
- 코드: `deploy/security-review.Dockerfile`, `scripts/prepare_service_image.py`,
  `scripts/verify_service_image.py`, `tests/container_review_support.py`, CI `service-image`.
- source commit에서 wheel을 만들고 service extra만 해시 검증해 설치한다. 비밀이나 저장소 전체를
  Docker build context에 넣지 않는다. 기본 UID와 실제 연결 시험의 범위를 명시했다.
- 준비: 공식 base digest 조회, 잠금 runtime requirements 오프라인 export, 로컬 ruff/Git
  whitespace 통과. 실제 CI image build/TLS/철회 결과는 실행 후 보충한다.
- `a33863c` [전체 CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42203712045)
  모든 작업 통과. `sova-test`의 실제 2개 DB/독립 서비스 연결 8개 시나리오도
  [609d115 CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42205726034) 통과.
  전체 Sova 로컬 회귀는 1110 PASS / 3 SKIP이며 외부 컨테이너·collector·AWS 환경 인수는 별도다.

### SVC-12 결과 및 네 번째 플랫폼 기준

- `893ddff` [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42207161356)는
  모든 작업 통과했다. 실제 이미지의 기본 UID 10001, 읽기 전용 root, capabilities 0,
  no-new-privileges와 service-only 의존성 9개를 확인했다. TLS/issuer 철회 1 PASS, 1.93초.
- 작업 중 develop은 `9e0d6a59d7a00925ddafc50cfa2ccad00c5ba768`로 8개 커밋 진행됐다.
  T13 실제 지문 기록, T9 ARM OpenBao pin, T43 GitOps image, T31 테스트 시계 변경이다.
  T10/T19 집행 코드 변경은 없다. 새 SHA를 네 번째 명시 기준으로 추가하고 기본값을 갱신했다.
- 새 기준 + 실제 PG/API의 계약·T10/TLS 체인·T7 시험: **32 PASS, 66.04초**.
  image job에도 새 기준의 initial/post_apply 정상·철회·단일 접수 10개 시나리오를 추가한다.
- [새 T13 실측](https://github.com/Softbank-Hackathon-Finals/platform/blob/9e0d6a59d7a00925ddafc50cfa2ccad00c5ba768/docs/evidence/t13-real-fingerprint-2026-11-06/README.md)은
  두 표 1행/2행의 데이터·스키마 MATCH다. 로컬 관리자·질의별 별도 트랜잭션이며 실제 실행기
  계정/동일 snapshot/시퀀스 보정/컷오버 인수가 아니다. 비공개 원본 digest도 없으므로 이 공개
  요약을 서명 원본으로 수입하거나 CTRL-06 전체 PASS로 바꾸지 않는다.

## SVC-13: 연동 토큰의 원래 수명과 단일 audience

- 기준 9e0d6a5. [ADR-0008](../adr/0008-service-token-use-boundaries.md)에 Salesloft Drift와
  NIST IR 8587 참고 근거, 실제 TokenReview의 교집합 동작, bearer 자격의 한계를 기록했다.
- 코드: `review_identity.py`, unit/integration identity 시험. 서비스 소비자만 단일 audience와
  원래 수명 600초를 요구하며 기존 TokenReview/UID/grant 확인을 유지한다. schema 변경 없음.
- `pytest tests/unit/test_review_identity.py -q`: **37 PASS**. 실제 Kubernetes API와 T7,
  최신 T10/TLS/PG 연결을 더한 잠금 Python 3.14 시험: **61 PASS, 85.04초**.
- API는 실제 발급한 복수 audience·3,600초 토큰을 각각 인증했다. 서비스는 둘 다 거부하고
  기존 600초 서비스 전용 자격은 허용했다. 전역 Kubernetes 토큰 정책이나 T7 코드는 변경하지 않았다.

## SVC-14: 실제 간접 DB 권한 우회 재현과 차단 조건

- 기준 9e0d6a5. [ADR-0009](../adr/0009-indirect-database-privileges.md)에 위협·선행 조건·관리자
  조치 경계를 기록했다. `review_database.py`, `review_server.py`, 실제 PG 회귀 파일을 수정했다.
- PUBLIC definer 함수와 owner-rights view로 다른 tenant의 합성 hold ID 읽기를 재현했다.
  직접 테이블 조회는 0행이었으나 기존 검사도 통과했다. 변경 전 새 시험은 2 FAIL이었다.
- 첫 수정은 PG17에 없는 large-object 검사 함수로 20 FAIL/27 PASS였다. 실제 catalog ACL
  검사로 수정한 뒤 DB 경계와 독립 TLS 서비스 묶음 **47 PASS, 19.73초**.
- 별도 관리자 PUBLIC 회수 후 직접 SQL도 거부되는 것을 확인했다. 서비스의 거부와 DB 자격의
  실제 권한 회수는 다른 동작이며, 서비스가 자동으로 팀 DB 권한을 변경하지 않는다.
- 플랫폼 DB와 같은 18.4의 공식 Docker index digest를 조회·확인해 image CI에 고정했다.
  기존 package CI의 PG17과 버전 간 동작을 대조한다. 결과는 해당 CI 이후 보충한다.
- `a78bac5` [토큰 보강 CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42208538564) 전체 통과.
  앞선 `97a6910` [image CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42207932376)도
  최신 플랫폼 initial/post_apply를 포함한 실제 컨테이너 연결 **11 PASS, 37.31초**였다.
- 잠금 Python 3.14 + 최신 플랫폼 + 실제 PostgreSQL/OPA/Kubernetes 전체 회귀:
  **847 PASS, 120.58초**. 새로운 간접 권한 검사와 토큰 수명 제한을 모두 포함한다.

### SVC-14 원격 결과

`269e1e5` [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42209971176) 전체 통과.
PostgreSQL 18.4를 실제 버전 값으로 확인하고 DB 경계 **40 PASS, 11.07초**, 실제 이미지/T10
연결 **11 PASS, 36.04초**를 확인했다. 기존 PG17 package 및 네 플랫폼 계약도 통과했다.

## SVC-15: 소비 컨테이너의 permit 만료와 중복 원본 수집

- `sova-test d1865f3`의 process 소비는 통과했으나 container 소비는 4 FAIL / 35 PASS였다.
  모든 실패는 효과 실행 전 permit 만료 거부다. 원래 만료 시각을 29~92ms 넘겼으며 이를
  정상 효과나 인수 성공으로 기록하지 않는다.
- [ADR-0010](../adr/0010-current-collection-authentication.md)의 명시적 current-collection
  callback을 도입했다. 기존 callback 의미를 바꾸지 않고 현재 원본 재조회·서명 검증·전체
  collection 일치가 하나의 검증에서 보장될 때만 중복 수집을 제거한다. 정확한 True만 허용한다.
- 수정: `application/security_program.py`, `adapters/registered_program.py`, `program_evidence.py`.
  단위 시험 **98 PASS**, 실제 PG/TLS/계측 **17 PASS, 11.24초**.
- 계측에서 원본 수집은 5회에서 3회로 감소했다. 현재 함수 호출 약 713만/1.956초는 계측값이며
  운영 SLA가 아니다. 기존 permit/결과 5초 기한과 접수 직전 재검사를 유지한다.
- 잠금 Python 3.14 + 기준 플랫폼 + 실제 PG/OPA/Kubernetes 전체 회귀: **867 PASS, 115.02초**.

### SVC-15 소비 CI 결과

생산자 `2898f54`를 고정한 Sova `4987c24` [CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42212461099)
process/container 모두 통과. 실제 컨테이너 소비 **39 PASS, 31.89초**이며 앞선 네 만료 실패를 해소했다.
부하가 더 크거나 원본이 바뀔 때의 만료/철회 거부 조건은 그대로 유지한다.

## SVC-16: 느린 TLS 응답의 공통 기한과 부가 정보 제한

- 요구/설계/한계: [ADR-0011](../adr/0011-shared-http-network-deadline.md).
  변경 전 실제 응답 지연 및 큰 헤더 시험 4 FAIL을 확인했다.
- 수정: `adapters/deadline_http.py`, `review_https.py`, `tests/integration/test_review_deadlines.py`.
  DNS 반환 뒤 TCP/TLS/send/read 전체의 남은 시간을 공유하고 HTTP metadata 누적 한도를 적용한다.
  DNS 자체 취소나 운영 전체 기한을 보장한다고 주장하지 않는다.
- 실제 TLS 정상/거부 및 identity 관련 **58 PASS, 8.16초**. 전체 잠금 런타임과 원격 소비를 이어간다.
- 잠금 Python 3.14 + 실제 PG/OPA/Kubernetes + 최신 플랫폼 전체 회귀 **879 PASS, 117.93초**.
  앞선 current-collection 생산자 [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42212375242)도
  Python 두 버전·플랫폼 네 기준·PG18 실제 이미지·secrets 모두 통과했다.
