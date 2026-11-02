# 지속 보안 개선 계약

이 문서는 구현된 계약·지원 범위·호스트 책임을 설명한다. 개발 과정 기록은 로컬에만 둔다. 침해 범위 제한, 근거 기반 실행, 복구 가능한 이전을 기반으로 취약점 평가와 보안 변경을 연결한다. 운영 자격이나 모든 취약점의 자동 수정을 선언하지 않는다.

## 자산·취약점·노출 평가

`AssetInventory`는 scope·자원 revision·source/image/configuration/SBOM digest·수집자·유효기간을 묶는다. `VulnerabilityScan`은 정확히 그 inventory와 OCI image digest에 결합한다. `ExposureObservation`은 별도의 신뢰된 관측 경로에서 도달 가능성·침해 징후·업무 중요도·악용 근거를 받는다. 보고서의 존재는 출처 인증이나 실행 중인 이미지 확인을 대신하지 않는다.

`RiskPolicy`는 현재 scope와 승인한 scanner invocation profile을 고정한다. profile에는 scanner·DB digest, 전체 패키지 포함, 미수정 항목 제외·억제 여부, severity 필터가 있다. 필터링·억제된 스캔, 불완전한 inventory, unknown severity·reachability·compromise는 완전한 평가로 승격하지 않는다. 악용이 확인된 항목은 조사 범위 미확인을 이유로 우선순위를 낮추지 않는다. 침해 의심이면 격리·조사, 침해 확인이면 증거 보존·깨끗한 재구축·자격증명 회전을 검토한다. 보고된 CVE가 없어도 침해 대응 필요성을 유지한다.

`AssessmentService`에는 인증한 actor의 authorize, 입력 인증, 현재 입력 조회, clock을 주입한다. 입력 scope·fingerprint를 확인하고, 외부 인증 뒤에 권한과 authority state를 재조회한다. 결과는 남은 근거 유효기간을 넘지 않는다. 이는 시점별 판정이며 실행 임대나 운영 변경 권한이 아니다. 호스트 실행기는 실제 변경 직전에 다시 게이트를 통과해야 한다.

## 보고서 어댑터

- CycloneDX JSON 1.5/1.6/1.7의 구성 요소를 제한된 inventory로 투영한다. 버전 누락·빈 inventory는 불완전 상태로 남긴다. 전체 표준의 모든 필드를 지원하는 schema validator는 아니다.
- Trivy JSON schema 2의 container image vulnerability profile을 지원한다. RepoDigests를 등록 image digest와 비교하며, 패키지 이름·버전과 선택적 PURL로 component를 연결한다. 알 수 없거나 모호한 연결은 거부한다. ArtifactID/ImageID를 OCI 배포 digest로 대체하지 않는다.
- 등록된 실행 profile의 include-all-packages와 모든 severity, suppression 정책을 별도 인증해야 한다. report body만으로 Trivy가 어떤 옵션으로 실행됐는지 증명할 수 없다.
- 입력은 최대 2MiB, JSON 중복 키·비정상 Unicode·NaN·과도한 깊이/노드 수를 차단한다. URL을 조회하거나 report 안의 명령을 실행하지 않는다. 알려진 필드만 투영하고 원본 설명/Instructions를 권한으로 사용하지 않는다.
- 원본 report·SBOM을 저장·전송할 위치와 데이터 분류는 호스트의 정책을 따른다. 정규화 과정이 비밀 제거·출처 서명 검증을 완료한 것으로 표시하지 않는다.

## 외부 계약 근거

- [Trivy JSON 보고서](https://trivy.dev/docs/latest/configuration/reporting/)
- [Trivy report 구조](https://github.com/aquasecurity/trivy/blob/main/pkg/types/report.go)
- [Trivy vulnerability 구조](https://github.com/aquasecurity/trivy/blob/main/pkg/types/vulnerability.go)
- [CycloneDX 1.6 JSON 규격](https://cyclonedx.org/docs/1.6/json/)

외부 도구가 실제로 실행됐다는 증거와 adapter parser 시험은 구분한다. 합성 시험의 SOVA-TEST advisory는 실제 취약점 번호가 아니다.

## Harbor 요청과 독립 검증

`RehearsalRequest`는 제안·정책·기준 소스/이미지·패치 artifact·파일별 전후 digest, sandbox runner/egress/verifier/test bundle digest, 등록 대상 snapshot과 유효기간을 묶는다. 지원 첫 프로필은 **등록된 regular-file 패치**이며 격리·재구축·자격증명 회전·데이터 이전 자체를 실행하는 runner는 제공하지 않는다. 해당 대응은 호스트 계획으로 연결해야 한다.

적용 범위는 source_only/target_only/both다. both는 source와 target의 정확한 scope와 별도 baseline image를 요구한다. 각 finding은 평가 decision fingerprint로 참조하며 `security-fix:<finding_digest>` 시험에서 수정 전 FAIL·수정 후 PASS를 요구한다. 기능 시험의 수정 전후 PASS와 목적지 호환성 시험도 별개다. 새 시험 이름이나 임의 PASS로 기존 의무를 대체하지 않는다.

이 프로필은 ASCII 정규 상대 경로만 지원한다. traversal·절대 경로·대소문자 충돌과 정책·독립 시험·검증기·워크플로·인증정보 변경은 거부한다. 보호 정책/신뢰된 test bundle을 수정해서 시험을 통과시키지 못하게 한다. 실제 파일이 regular file인지와 전체 변경 manifest의 정확성은 샌드박스 및 독립 verifier가 검사해 서명해야 한다. 패키지의 경로 검사만으로 호스트 파일시스템을 격리했다고 표현하지 않는다.

`RehearsalReceipt`는 실제 변경 manifest, 대상별 검사한 image digest, test proof, 메타데이터/egress 차단 결과, production credential 부재, 시간·메모리 사용을 반환한다. 누락/중복/추가 scope, 다른 이미지·시험 묶음, 결과 UNKNOWN/FAIL, 자원 초과, 만료는 admission을 차단한다. 보고된 자원 사용과 네트워크 시험이 진짜인지 확인하는 주체는 등록된 독립 verifier다.

`RehearsalReceiptAuthority`는 기존 Ed25519 근거 형식을 재사용한다. receipt 전체 fingerprint와 모든 대상 inventory가 근거에 결합되고, key registry가 각 대상 scope와 verifier version을 허용해야 한다. 키 폐기·회전과 대상 revision을 재조회한다. 단순 해시 일치나 AI의 '성공' 답변은 근거 인증이 아니다.

`RehearsalAdmissionService`는 현재 source assessment, 각 target inventory, 요청 폐기 상태, actor 권한과 독립 근거 인증을 확인한다. 외부 callback 이후 변경·만료가 생기면 거부한다. 결과가 allow여도 운영 적용 권한은 없다. 실행 직전 공통 승인/실행기가 다시 유효성을 확인해야 한다.

`HarborRehearsalPort`는 submit/inspect의 팀 연결 계약이다. 실제 Harbor 환경 생성·도구 실행·자격증명·리소스 한도 강제는 Harbor 담당이 구현한다. 불확실한 submit은 같은 durable operation/key로 조회하며 새 key로 자동 재요청하지 않는다.

## 직렬화와 API 경계

`modernization_codec`는 등록된 v1 kind만 디코드한다. 알 수 없는 key/type/version, bool을 int로 바꾸는 형식 혼동, naive timestamp, 유효하지 않은 enum을 거부한다. pickle이나 입력된 Python module/type 이름을 실행하지 않는다. 해시·서명은 이 문서의 정규화 규칙을 사용하며, 디코드 성공은 권한 부여나 issuer 인증을 뜻하지 않는다.

## 승인·실행 연결

`compile_patch`는 현재 등록된 대상 inventory와 검증된 산출물을 기존 `LifecyclePlan`으로 변환한다. 새 승인 엔진이나 효과 실행기를 만들지 않는다. 대상별 adapter는 호스트 레지스트리에서 받으며 source/image/configuration/provenance digest가 고정된 `apply-verified-patch` 단계만 만든다. 이 plan은 **미승인 상태**다. 호스트의 저장된 승인, 소유권·epoch·효과 CAS와 기존 필수 게이트를 모두 통과해야 한다.

`PatchExecutionGuard`는 매 실행 직전에 등록 요청·receipt·독립 검증·대상 inventory·권한·활성 보안 보류를 확인하고 plan 전체를 다시 구성해 비교한다. 일반 패치 승인은 사고 보류를 해제하지 않는다. 교차 환경 패치는 양쪽 별도 리허설과 inventory가 필요하며, 단계별 완료가 있어도 전체 성공은 마지막 필수 검증 전까지 선언하지 않는다.

`patch_rehearsal_records`가 만드는 것은 독립 verifier가 서명할 정규화된 근거이며, 생성만으로 신뢰되지 않는다. 호스트는 서명/발급자 인증을 생략해서는 안 된다. `require_postflight`는 실행 후 관측이 승인된 image/source/configuration/provenance, 정확한 effect command와 맞고 기능·수정 효과·보호 시험이 모두 PASS인지 확인한다. 과거 APPLIED 이력은 현재 건강 상태의 근거가 아니다. 적용 후 결과가 불명확하면 같은 효과를 재실행하거나 자동 롤백하지 않고 보류·읽기 전용 조회·별도 복구 승인을 사용한다.

Sova의 `PatchPlanExecutionService`는 이 guard를 기존 `StoredPlanExecutor`에 호출별로 합성한다. 실행 중 응답 유실 또는 실행 후 검증 실패는 보안 보류 기록으로 연결한다. 보류 저장소 실패는 성공으로 삼키지 않으며 운영 작업의 실패/복구 상태로 처리해야 한다. 실제 이미지 교체 adapter와 Harbor 실행 환경은 별도 호스트 구현·자격 시험이 필요하다.

## 보안 산출물 저장

`PostgresSecurityArtifacts`와 `postgres_modernization_v1.sql`은 정규화된 산출물을 내용 digest로 저장하고 등록·폐기 이벤트를 추가한다. 이미 저장한 내용을 덮어쓰거나 폐기한 digest를 재등록하지 않는다. 요청에 연결된 receipt/decision은 등록된 부모 요청을 통해 scope를 확인한다. 폐기는 revision 1→2 CAS이며 동일 산출물을 두 검토자가 동시에 폐기하면 하나만 성공한다.

마이그레이션 적용은 관리자 책임이다. runtime에는 SELECT/INSERT만 부여하고, FORCE RLS와 비소유자·NOBYPASSRLS 역할을 사용한다. DB 행의 존재는 issuer 인증이나 사람 승인을 의미하지 않는다. 호출자가 임의 tenant 설정을 할 수 있는 공유 DB 자격증명 탈취까지 격리했다고 주장하지 않는다. 실행 시에는 산출물과 부모 요청의 활성 상태를 함께 재조회해야 한다. 운영 배포 전에 역할별 권한·보존·용량·백업 정책을 별도 검증한다.
