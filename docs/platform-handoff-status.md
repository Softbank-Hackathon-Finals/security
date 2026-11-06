# 플랫폼 보안 연동 인계 현황

2026-11-06. 작업 위치는 `security`와 `sova-test`의 `feature/security-service-integration`이다.
팀 `platform`의 코드·운영 환경은 변경하지 않았다. 두 제안서의 요구를 구현하고 개인 환경에서
소비·실패 경계를 검증한 단계이며, 팀 환경 배포 및 보안 인수가 끝났다는 뜻은 아니다.

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
| 감사·자원 제한 | 입력·시간·worker·감사 크기 제한, 부분 쓰기 후 거부 | T24 외부 불변 보관·용량 경보·권한·회전 절차 |
| 공급망 | 정확한 source/lock/wheel/image 입력, 설치 도구 제거, 전체 OS/Python 재고 대조 | 현재 이미지 BLOCK 해소, 기존 발행/서명 경로의 registry digest |

원문별 상세 매핑은 [두 문서 연결](architecture-integration.md), 팀 통제별 범위는
[플랫폼 통제 대응표](platform-control-traceability.md), 실행·설정 계약은
[서비스 안내](security-review-service.md)를 따른다.

## 검증 기준과 결과

소비 기준 producer는 `5ddf281b31568e49cdd1a2c993e8d8172cdc7b1e`, 기본 platform은
`98885a69999398bfe3f49fbc8324a7b19aae3e16`다. 앞선 일곱 플랫폼 SHA도 계약 CI에 유지한다.
동명 `0.11.0` 버전만으로 선택하지 말고 [배포 산출물 계약](distribution.md)의 source/lock/wheel hash를 확인한다.

- [Producer CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42238259304):
  Python 3.14 **1,008 PASS / 2 SKIP**, 여덟 플랫폼 기준 성공. skip은 별도 장시간 시험과 CA 등록형 HBA다.
  이 실행의 30분 지속 시험은 별도 job이며 완료 여부는 아래 지속 시험 원본에서 확인한다.
- 같은 CI의 실제 PostgreSQL 18.4 권한 **54 PASS**, TLS/HBA **1 PASS**, 서비스 image/T10 **11 PASS**.
- [DB 생성 제한 수정 전후](evidence/reader-storage-2026-11-06/README.md): PG17.11 수정 전
  네 작업 허용 실패를 직접 재현하고 수정 후 거부/권한 drift 12개를 통과했다.
- [Sova 복원 회귀](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42227270467):
  process/container 성공, container **42 PASS**. 이 실행의 producer는 d9c878f이며 최신 pin 소비는 별도 기록한다.
- [지속 시험 원본](evidence/review-endurance-2026-11-06/README.md): 코드 SHA·실측 시간·자원·종료를 구분한다.
  합성 issuer/측정 내용과 실제 PG/TLS/프로세스를 구분하고, 실패한 로컬 실행을 성공에 합산하지 않는다.
- [이미지 원본](evidence/service-image-scan-2026-11-06/README.md): OS 87개/Python 10개 대조,
  **HIGH 49건(고유 CVE 13개)으로 배포 BLOCK**. 수집 CI 성공은 보안 정책 PASS가 아니다.

개별 변경 이유·실패 재현·재검증은 [개발 기록](development/security-service-2026-11-06.md)에 있다.
운영 환경의 모든 권한·네트워크·백업·업무 복원을 시험한 결과로 확대하지 않는다.

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
[T28 재시작 경계](evidence/t28-restart-boundary-2026-11-06/README.md)에서는 결과 기록 전 중단 후
모의 효과가 재호출됐다. 운영자 JSONL을 별도 집행 정본으로 채택하지 않으며 기존 T10/T31의
영속 접수·현재 권한·실제 효과 조정을 유지한다. 플랫폼 T10 원장에 같은 결함이 있다는 주장도 아니다.
