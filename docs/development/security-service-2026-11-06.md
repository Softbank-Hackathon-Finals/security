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
