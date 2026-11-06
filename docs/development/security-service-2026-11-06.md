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
