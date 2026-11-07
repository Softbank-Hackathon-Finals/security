# 플랫폼 보안 연동 인계 현황

2026-11-07 KST. 작업 위치는 `security`와 `sova-test`의 `feature/security-service-integration`이다.
팀 `platform`의 코드·운영 환경은 변경하지 않았다. 두 제안서의 요구를 구현하고 개인 환경에서
소비·실패 경계를 검증한 단계이며, 팀 환경 배포 및 보안 인수가 끝났다는 뜻은 아니다.

이번 후속 범위는 이미지 HIGH 49건 해소, T28 재시작 경계, 실제 인수 준비다.
실환경 로그인·검증은 사용자가 데모용 맥에서 후속 진행하도록 지정했다.
[실환경 인수 실행안](platform-live-acceptance.md)에 `bravo-personal` SSO/SSM,
`platform-state` 읽기 전용 범위와 일괄 배포 후 확인 순서를 남겼다. 온프렘 목적지 설정과 구분한다.
[데모 맥 인계](demo-mac-handoff.md)에 아키텍처별 exact archive 다운로드와 해시 대조 순서를 모았다.

## 인계할 구조

`security`는 공통 정책·증거 계약과 제한된 읽기 전용 판정 서비스의 정본이다.
`sova-test`는 실제 두 PostgreSQL 원장과 TLS 프로세스/컨테이너를 연결하는 소비 시험 환경이다.
플랫폼의 T7/T9 발급·비밀 관리, T10 승인·잠금, T19 기존 판정, T31/T12 실행·복구 책임을 유지한다.
새 발급기나 실행 엔진을 만들지 않았다. 원격 PASS만으로 실행하거나 보류를 해제할 수 없다.

| 요구 | 구현·검증한 범위 | 인계 시 남은 조건 |
|---|---|---|
| 두 문서의 보안 속성 | 이전 22개·패치 19개 검사, 원문 ID/해시, 사전·사후 분리 | 실제 각 생산자의 서명 근거·현재 환경 revision 연결 |
| 수동 키 의존 축소 | 현재 TokenReview, 단일 audience·짧은 수명, SA UID, mounted credential 회전 | 내부 projected token/UID 인수, 외부 T7 audience 확장 |
| 침해 범위 제한 | 테넌트 전용 SELECT/FORCE RLS, 관리자 함수·쓰기·TEMP/대형 객체 생성 거부, DB별 HBA 렌더러 | 전용 DB PUBLIC 권한 준비, CNPG 실제 규칙 순서·pooler 신원·CNI/다른 DB 거부 |
| 승인된 변경만 실행 | 원래 T10 authority와 현재 등록/계획 잠금 결합, 단일 접수 | 운영 writer의 같은 잠금, 직접 실행 IAM/RBAC 경로 제한 |
| 장애·철회·응답 유실 | 사전 효과 0회, 사후 APPLIED/hold 유지, 재적용 없음 | 운영 실행기 원장 조정·별도 복구/해제 승인 |
| 복원 뒤 신뢰 회귀 | 보안 DB의 과거 trust 복원에도 별도 호스트 hold 유지 | 복원과 독립된 차단/체크포인트, 최신 철회 재등록·실제 PITR |
| 감사·자원 제한 | 입력·시간·worker·DB 역할 연결 수·감사 크기 제한, 부분 쓰기 후 거부 | T24 외부 불변 보관·전체 DB 예산·용량 경보·권한·회전 절차 |
| 공급망 | native amd64/arm64의 전체 OS/Python 대조, HIGH/CRITICAL 0건 PASS, 격리 scanner와 exact image archive | 기존 발행/서명 경로의 registry digest와 실제 반입·운영 인수 |

원문별 상세 매핑은 [두 문서 연결](architecture-integration.md), 팀 통제별 범위는
[플랫폼 통제 대응표](platform-control-traceability.md), 실행·설정 계약은
[서비스 안내](security-review-service.md)를 따른다.

## 검증 기준과 결과

소비 기준 producer는 `546f6e0482cc06fa32f00ea8d554522551a84beb`, 기본 platform 개발 계약은
`0795f65e24f58e43545b16b97757efcc0923fd4a`다. 현재 GitOps 호스트 발행 원본인
`445848d2ed9878e31eb6f5aabad0575c61739b47`과 앞선 10개 기준을 포함해 총 12개 계약을 검증한다.
실제 host binding에는 확인한 runtime source를 명시한다. develop SHA를 운영 이미지 source로 대신하지 않는다.
동명 `0.11.0` 버전만으로 선택하지 말고 [배포 산출물 계약](distribution.md)의 source/lock/wheel hash를 확인한다.

- [Producer CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42265872242):
  Python 3.14 **1,084 PASS / 2 SKIP**, 12개 플랫폼 기준 성공. skip은 별도 장시간 시험과 CA 등록형 HBA다.
  최신 0795f65와 발행 source 445848d는 각각 소비·재평가 **34 PASS**다.
- 같은 CI의 실제 PostgreSQL 18.4 권한 **58 PASS**, TLS/HBA **1 PASS**, 서비스 image/T10 **11 PASS**.
- [DB 생성 제한 수정 전후](evidence/reader-storage-2026-11-06/README.md): PG17.11 수정 전
  네 작업 허용 실패를 직접 재현하고 수정 후 거부/권한 drift 12개를 통과했다.
- [Sova 최종 소비 CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42266814087)는
  producer 546f6e0을 고정해 process **44 PASS / 67.36초**, container **44 PASS / 48.77초**다.
  기존 두 PG·TLS와 승인/효과/복원 hold 경계를 그대로 유지한다.
- 같은 CI의 [T28 최신 소비](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42266814087):
  최신 driver **36 PASS**, 이전 driver **32 PASS / 4 SKIP**. 실제 process 종료·PG recovery와
  지연 HTTP 효과·명령 인자·조회 subprocess 우회를 개인 환경에서 검증했다.
- [지속 시험 원본](evidence/review-endurance-2026-11-06/README.md): 코드 SHA·실측 시간·자원·종료를 구분한다.
  3시간·90분·30분 두 실행을 각각 완료했으며 최신 자원 제한 수정은 마지막 30분 source에 포함된다.
  합성 issuer/측정 내용과 실제 PG/TLS/프로세스를 구분하고, 실패한 로컬 실행을 성공에 합산하지 않는다.
- [이전 이미지 원본](evidence/service-image-scan-2026-11-06/README.md)은 HIGH 49건의 BLOCK을 보존한다.
  [Alpine native 양쪽 재검증](evidence/service-image-scan-2026-11-07/README.md)은 OS 38/Python 10개를
  정확히 대조하고 **전체 심각도 0건 / PASS**다. 미수정 취약점 예외를 추가하지 않았다.
  검사한 exact image archive를 저장·재로딩하고 inventory를 대조했다. 발행·서명·배포는 별도다.

개별 변경 이유·실패 재현·재검증은 [초기 개발 기록](development/security-service-2026-11-06.md)과
[후속 개발 기록](development/security-acceptance-2026-11-07.md)에 있다.
운영 환경의 모든 권한·네트워크·백업·업무 복원을 시험한 결과로 확대하지 않는다.
이미지 실측은 native `linux/amd64`·`linux/arm64` 각각이며, Sova 소비와 실제 플랫폼 운영 결과는
분리한다. ABI 변경 후 두 이미지의 [90분 연속 시험](evidence/review-container-endurance-2026-11-07/README.md)은
별도 source 4511a43에서 각각 5,400.001초를 완료했다. 정상 360회·자격/grant 철회 거부 각 180회·
만료 거부 176회, RSS 증가 약 1.1MiB와 FD/thread 유지, 소유 컨테이너 정리를 확인했다.
최종 546f6e0 이미지 자체의 90분 관찰로 바꾸어 쓰지 않는다.

## 플랫폼 연결 순서

1. 담당 공급자가 현재 계획·환경 revision·profile version·initial/post_apply·application_id를 등록한다.
   각 증거의 원본 시각·서명·철회를 보존한다. 과거 TLS 성공을 전체 22개 검사 충족으로 바꾸지 않는다.
2. 운영자는 전용 SA/DB reader/CA/보호된 mount/PVC와 현재 발급 경로를 구성한다. 명세·HBA 및
   [전용 DB 준비 SQL](adr/0019-reader-storage-creation-boundaries.md)은 렌더링만 하며 자동 적용하지 않는다.
   공유 DB의 PUBLIC 권한 변경은 다른 사용자의 필요 권한을 먼저 검토한다. 실제 허용 대조군과 타 tenant/DB/권한 거부를 확인한다.
3. 읽기 전용 shadow로 차이를 관찰한다. `matched=true`는 두 결과가 같은 UNKNOWN/FAIL일 수도 있다.
   새 `WorkflowHost`의 prepared reader와 SHIFT 실행 접수의 책임을 분리한다.
4. 원본 증거·운영 권한 시험이 충족된 경로만 기존 T10 집행에 연결한다. plan lock 아래 현재 승인과
   등록을 재검사한다. 서비스 장애 시 신규 위험 변경은 보류하고 기존 앱은 계속 제공한다.
5. 이미 적용된 작업은 원장으로 조정한다. 보안 DB/호스트 원장 복원 전에 독립 실행 차단을 유지하고,
   최신 철회·실제 효과·백업/데이터/업무를 확인한 뒤 별도 승인을 거쳐 해제한다.

T19의 이전 두 앱은 같은 출발지 DB를 사용했다는 정정이 있다. 현재 창의 독립 DB 신원과
양쪽 경로별 원본을 새로 수집해야 한다. T22의 브라우저 재접속도 DB 컷오버 증거로 대신하지 않는다.
운영 계정·외부 발급·CNI·T24·백업 저장소가 필요한 항목은 이 인계 조건으로 남겼다.

98885a6의 T19 공개키 원장은 기존 plan view/잠금과 결합하여 승인 후 키 철회를 확인했다.
7edab53의 공개 서명 원장도 새 인스턴스 재조회에서 원래 만료를 보존하고 현재 철회를 반영한다.
단계별 host 구현이 추가됐지만 운영 ANALYZE/PROPOSE/WATCH ports·현재 생산자 연결은 별도 인수다.
[T28 재시작 경계](evidence/t28-restart-boundary-2026-11-06/README.md)에서는 결과 기록 전 중단 후
모의 효과가 재호출됐다. 운영자 JSONL을 별도 집행 정본으로 채택하지 않으며 기존 T10/T31의
영속 접수·현재 권한·실제 효과 조정을 유지한다. 플랫폼 T10 원장에 같은 결함이 있다는 주장도 아니다.
개인 Sova의 DurableT28Port는 기존 실행 원장을 사용해 이 재호출을 차단한다. 원본 플랫폼 CLI는
변경하지 않았으므로 실제 조립과 직접 실행 권한 제한은 인계 조건이다. 최신 T24는 기존 SSE
`follow`를 재사용하며, 승인과 반영 주체 분리·실행 직전 T19 재평가를 유지한다.
# T14·T33 후속 인수 준비 (2026-11-07)

새 패키지 0.11.1은 최신 T33 계약 선택과 인증 중 철회·만료 경계를 보강하고,
T5 full:1의 20개 시험을 그대로 읽는 오프라인 인수 목록을 제공한다.
[맥 인수 실행 안내](mac-t14-t33-intake.md)와 [개발 기록](development/security-intake-2026-11-07.md)을 따른다.
이 추가 작업의 원문 인증·실제 AWS/GCP/온프렘 인수는 미완료다. 아래 과거 native 이미지와
90분 결과의 source를 새 버전의 결과로 자동 변경하지 않는다.
