# Harbor 실행·독립 검증 연결 계약

이 문서는 Harbor 담당 구현과 `sova-security`의 연결 기준이다. Harbor 실행기·격리 환경은 이 패키지가 구현하지 않는다. 기존 Sky의 배포 판단 프롬프트와도 별개다.

## 책임 경계

| 담당 | 책임 |
| --- | --- |
| 플랫폼 | 사용자·조직 인증, 등록 대상·자산·정책, 작업·outbox·실행권·사람 승인 |
| 보안 패키지 | 요청/산출물 결합, 위험 평가, 독립 근거 인증, 실행 게이트, 사후 재평가 |
| Harbor 실행기 | 지정한 환경의 격리 실행·빌드·자원/통신 제한, 작업 조회·취소·산출물 전달 |
| 독립 verifier | 보호된 시험 묶음 실행, 실제 결과 수집, 변경 manifest·산출물·근거 서명 |
| 배포 adapter | 등록된 자원과 승인된 digest만 적용, provider readback·복구 계약 |

에이전트와 실행 샌드박스는 운영 자격증명이나 verifier의 서명 키를 받지 않는다. 검사 도구는 Trivy 등 기존 도구를 사용한다. signer와 독립 시험은 에이전트가 바꿀 수 없는 경계에 둔다.

## 1. 요청

`RehearsalRequest`는 호스트가 등록한 불변 객체다. `modernization_codec.encode/decode`를 사용한다. 임의 Python 타입, pickle, shell 명령 또는 URL을 공개 계약에 추가하지 않는다.

| 값 | 검증 대상 |
| --- | --- |
| proposal | 평가·정책·기준 source/image/configuration·패치 artifact digest |
| changes | 허용된 regular file의 전후 digest와 경로 |
| profile | runner/verifier image·egress policy·test bundle digest, 시간·메모리 한도 |
| targets | source/target의 정확한 scope, inventory snapshot, 기준 이미지 |
| requirements | 대상별 수정 전후 시험 의무 |
| verifier_issuer | 등록된 독립 발급자. 제안자와 같을 수 없음 |
| 유효기간 | 제안의 기한을 연장하지 않는 요청 기한 |

첫 패치 프로필은 정책·신뢰된 시험·워크플로·인증정보 경로 변경을 거부한다. `pyproject.toml`도 현재 보호 목록에 있다. 지원하지 않는 변경은 별도 프로필 자격 시험이 필요하며, 보호 규칙을 제거해 우회하지 않는다. 경로 검사만으로 symlink나 호스트 파일시스템 격리가 증명되지는 않는다.

## 2. 제출·조회

`HarborRehearsalPort.submit(request, idempotency_key=...)`는 durable 작업 ID를 반환한다. 같은 등록 요청의 재접수는 같은 효과로 연결해야 한다. 응답이 유실돼도 새 key나 다른 환경으로 자동 제출하지 않는다.

`inspect(operation_id)`는 대기 중이면 `None`, 완료되면 독립 검증 receipt를 제공한다. receipt와 서명 envelope의 전달·저장은 별도 호스트 연결에서 수행한다. 단순한 agent 종료 코드 0을 receipt로 대신하지 않는다.

## 3. 필수 시험

각 대상에 다음 시험이 필요하다. `both`는 양쪽 scope에 별도 결과를 요구한다.

| 시험 ID | 수정 전 | 수정 후 |
| --- | --- | --- |
| `security-fix:<finding fingerprint>` | FAIL | PASS |
| `functional` | PASS | PASS |
| `compatibility` | 등록 의무에 따름 | PASS |
| `data-safety` | PASS | PASS |
| `protection` | PASS | PASS |

`data-safety`는 데이터 연결·보존·스키마 영향 등 지원한 프로필의 실제 시험이다. 데이터가 없는 앱도 등록된 조사로 그 조건을 확인해야 하며 임의 N/A로 통과하지 않는다. 일반적인 스키마 변경이나 모든 앱의 무중단을 보증하는 시험은 아니다.

메타데이터 접근 거부·egress 거부, 운영 자격증명 부재, 실제 시간·메모리 한도 결과도 필요하다. 제한 설정이 존재한다는 선언과 실제 접근 거부 결과를 구분한다. 시험 bundle·verifier 또는 파일 manifest가 바뀌면 기존 결과를 사용하지 않는다.

## 4. 산출물과 서명

`TestedArtifact`에는 대상 scope와 image/source/configuration/provenance digest가 들어간다. source와 image가 실제로 연결되는 빌드 근거를 검증해야 한다. 로컬 image ID나 mutable tag를 OCI manifest digest로 대신하지 않는다.

`TestProof`는 scope·시험 ID·before/after·관측 image digest·결과·로그 근거 digest·관측 시각·기한을 포함한다. `RehearsalReceipt`는 전체 manifest·산출물·시험·sandbox 보호 결과를 묶는다.

독립 verifier는 `rehearsal_evidence(...)`의 정규화 record를 서명한다. 호스트의 `RehearsalReceiptAuthority`는 등록된 공개 키, 발급자, verifier version, 모든 대상 scope와 폐기 상태를 확인한다. 해시 일치나 서명 파일의 존재만으로 인증하지 않는다. 서명 키는 이 계약이나 브라우저에 포함하지 않는다.

## 5. 승인 이후

리허설 PASS는 운영 변경 권한이 아니다. `prepare_patch`는 기존 LifecyclePlan과 binding만 생성한다. 요청 작성자·verifier와 분리된 승인자가 plan을 승인하고, 기존 원장·실행권·보안 보류를 거쳐 실행한다.

양쪽 리허설이 통과해도 계획 하나는 명시한 환경 하나만 변경한다. 다른 환경을 바꾸려면 현재 상태를 다시 조사해 계획·승인을 만든다. 변경 전 snapshot으로 양쪽을 연속 적용하지 않는다.

실행 후에는 실제 artifact readback, 기능·보호 시험, 새 스캔을 통한 `PatchReassessment`가 필요하다. runtime 관측은 해당 reassessment digest와 정확한 command에 연결해 별도 서명한다. 기존 취약점 잔존·새 항목·심각도 증가·미확인·신뢰 폐기는 보류 대상이다. 응답 유실이나 사후 실패를 자동 재실행·자동 롤백으로 처리하지 않는다.

## 연결 완료 판정

- 등록한 request와 실제 실행의 모든 digest가 일치한다.
- 운영 자격증명 없이 실제 시험이 실행된다.
- 에이전트가 시험·verifier·서명 키를 바꾸지 못한다.
- 누락·위조·만료·scope 변경·키 폐기를 거부한다.
- 응답 유실 뒤 동일 작업을 조회하며 중복 실행하지 않는다.
- 실제 배포 adapter와 사후 검증까지 별도 통합 시험을 통과한다.

패키지의 합성 계약 시험, 실제 서명·PostgreSQL 시험, 실제 Harbor 실행 시험, 운영 배포 자격은 각각 구분한다.
