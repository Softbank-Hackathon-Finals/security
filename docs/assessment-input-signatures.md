# 평가 입력의 서명 인증 연결

`AssessmentInputAuthority`는 기존 `AssessmentService.authenticate_input`과 `RehearsalAdmissionService.authenticate_input`에 연결하는 구체 어댑터다. 기존 Ed25519 envelope, 발급자 원장과 scope·verifier version 검증을 사용한다. 암호 알고리즘이나 별도 승인 엔진을 만들지 않는다.

## 입력 역할 분리

지원하는 입력 종류는 고정돼 있다. 임의 문서 타입이나 입력 JSON의 클래스 이름을 로드하지 않는다.

| 문서 kind | 등록할 발급 역할의 예 |
| --- | --- |
| `asset-inventory.v1` | 자산 수집기 |
| `vulnerability-scan.v1` | 스캐너 수집 서비스 |
| `exposure-observation.v1` | 노출·침해 상태 검증기 |
| `risk-policy.v1` | 조직 정책 발급 서비스 |
| `risk-assessment.v1` | 결정적 평가 서비스 |
| `rehearsal-request.v1` | 인증된 요청 접수 서비스 |

서명 record의 verifier version은 `sova.security.assessment-input.<kind>`, 의무 ID는 `assessment-input:<kind>`다. 정책 발급 키와 일반 수집 키를 같은 권한으로 등록하지 않는다. 발급자의 `allowed_verifiers`와 `allowed_scopes` 양쪽을 제한한다. 이름만 다른 역할이 같은 무제한 키를 공유하면 역할 분리가 성립하지 않는다.

## 서명할 값

`assessment_input_record(value, revisions=..., evidence_id=...)`는 문서 전체 fingerprint, 고정 kind, 문서 scope와 원래 관측·만료 시각, 현재 등록 revision을 기존 `EvidenceRecord`에 묶는다. 원본 코드·비밀값·보고서 전문은 record에 포함하지 않는다.

독립 발급자는 이 record를 `Ed25519EvidenceSigner`로 서명한다. 수신자는 현재 앱의 등록된 issuer와 키를 조회하고, 다음 항목을 모두 확인한다.

- 호출자 권한과 문서의 정확한 tenant·app·environment·resource
- 문서 kind별 허용 issuer 및 verifier version
- source·configuration·policy·environment revision
- 전체 문서 fingerprint와 서명 payload
- 원래 근거 기한과 키의 유효기간·폐기 상태
- 인증 중 revision·issuer 역할·envelope·신뢰 정보 변경

지원하지 않는 문서, 다른 자원으로의 재라벨링, False 인가 응답, 폐기·만료 키는 거부한다. 원래 입력의 기한을 새 인증 시각부터 다시 계산하지 않는다.

## 호스트 연결

호스트는 `envelope_provider`, `current_revisions`, `issuers_for`, `resolve_trust`, `authorize`, `clock`을 제공한다. 이 공급자는 인증된 저장소·등록 상태를 읽어야 한다. 브라우저가 제출한 issuer·revision·공개 키를 그대로 반환하는 공급자는 인증 경계가 아니다.

`resolve_trust`에는 기존 `PostgresVerifierRegistry.resolve`를 연결할 수 있다. envelope는 기존 `PostgresSignedEvidence`에 불변 저장한다. `evidence_id`와 문서 fingerprint의 조회 관계도 호스트가 등록하며, 사용자가 다른 앱의 record ID를 임의로 골라 조회하지 못하게 한다. 단순 해시 일치만 확인하는 콜백으로 이 어댑터를 대체하지 않는다.

키 회전 시 새 key ID와 새 evidence ID로 다시 발급한다. 폐기된 키를 활성화하거나 기존 envelope 행을 다른 서명으로 덮어쓰지 않는다. 등록·폐기는 기존의 별도 관리 승인 경계를 따른다. 검증 중 변경은 성공으로 반환하지 않고, 다음 읽기에서 새 상태를 확인한다.

## 인증과 사실 검증의 차이

유효한 서명은 **해당 역할의 발급자가 이 문서를 발급했다는 근거**다. 스캔의 완전성, source와 이미지의 실제 일치, 노출 상태 또는 정책의 적절함을 자동으로 증명하지 않는다. 발급자·수집기의 자격 시험, 원본 해시 검증, 결정적 위험 평가와 독립 리허설을 계속 수행해야 한다.

이 어댑터는 읽기 검증이며 운영 실행 권한을 발급하지 않는다. 서명 검증과 원격 IAM·배포 효과 사이에 분산 트랜잭션이 생기는 것도 아니다. 실제 변경 직전 기존 guard를 다시 실행하고, provider의 revision 조건과 실행 fencing을 적용해야 한다.

## 검증 범위

실제 Ed25519 키를 사용하는 평가·리허설 연결, 역할·scope·revision 변경, 키 폐기, 부정 인가를 시험한다. 별도 임시 PostgreSQL에서는 원본 envelope가 그대로 남아 있는 상태에서 발급자 원장을 폐기하고, 이후 입력 인증이 거부되는지 확인한다.

이는 기업 인증·운영 key broker·KMS/HSM·실제 수집기 배치가 완료됐다는 뜻이 아니다. private key는 에이전트나 이 계약에 넣지 않으며, 운영 발급 환경과 키 보호는 호스트가 구성해야 한다.
