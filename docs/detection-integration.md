# 팀 탐지 계약 연결

`adapters.team_detection.import_detection`은 플랫폼의 T33 OCSF 1.1 부분집합을 읽는다. 기준은 platform 커밋 `cbb03cdb705719c94c7ad84fa8aa44f08a1b480b`의 `docs/security/detection/finding.schema.json`이며 패키지에 보관한 schema SHA-256은 `22ad580baf4854ef1d272a497ebe708ef48a65d47fc3840eb2d00b3fa441f8b1`이다. 이후 팀 변경을 자동으로 신뢰하지 않는다. 계약 갱신 시 예제·상호운용 시험과 함께 명시적으로 반영한다.

## 수집과 권한의 구분

입력은 이미 정규화한 Finding 또는 SourceStatus다. 이 패키지가 Falco·GuardDuty·Security Hub·SCC·Kyverno의 탐지 엔진이나 수집 서버를 대체하지 않는다. 원본 URL·명령·자유 서술은 실행·조회하지 않으며, 투영에는 원본과 정규화 보고서의 hash 및 분류만 남긴다.

등록은 정확한 tenant/app/environment/resource, 출처, 계정·리전, 자원 UID·현재 리비전, 필요 시 namespace, 짧은 신선도 기한을 지정한다. 마스킹된 자원 ID나 환경 이름만으로 앱 소유권을 추정하지 않는다. 인증된 수집자가 별도로 확보한 자원 UID·리비전과 일치해야 한다. 복수 자원·매핑 누락은 개별 앱의 변경 권한으로 사용하지 않는다.

JSON Schema 통과는 인증이 아니다. `DetectionAdmission`은 현재 등록과 정확한 typed observation의 서명을 각각 검증한다. 기존 `AssessmentInputAuthority`의 scoped Ed25519 검증·현재 키 폐기·발행자 역할 분리를 재사용할 수 있다. 등록 서명 역할과 수집 서명 역할은 운영자가 별도로 지정한다. 서명은 출처를 인증하며, 손상된 수집자의 주장이 사실임을 보증하지 않는다.

## 판정과 제한

| 입력 | 처리 |
| --- | --- |
| 활성 Detection Finding | `detected-threat` 보류. 공격 확정·자동 격리 권한은 아님 |
| 활성 취약점·정책 Fail | 관측에 맞는 보류 |
| 알 수 없는 등급·상태, Warning | 미검증 보안으로 보수적 보류 |
| 수집 FAILED/STALE/DISABLED·오래된 heartbeat | 탐지 공백으로 보류. 0건·정상으로 표시하지 않음 |
| 신선한 OK heartbeat | 수집 가용성 관측만 기록. 앱이 안전하다는 판정 아님 |
| sample finding | 시험 출처를 유지하고 실제 사고 보류는 만들지 않음 |
| Resolved/Suppressed/Close | 수명주기 기록만 저장. 기존 사고 보류는 해제하지 않음 |

보류는 source·scope·finding의 안정된 식별자로 중복 제거한다. 승인·배포·격리·키 회전·보류 해제를 이 입력으로 자동 수행하지 않는다. 해제는 기존의 분리 승인·재검증 절차를 따른다. 저장 장애나 뒤늦은 인증 실패가 이미 설정한 보수적 보류를 되돌리지 않는다.

## 검증 범위

고정된 정규화 시험 데이터로 계정·리전·환경·자원·리비전 불일치, 미래/만료, 중복 JSON 필드, 숫자 타입 혼동, 샘플·해결 상태, 서명 재사용 거부를 검증한다. 실제 PostgreSQL과 Ed25519로 보류 중복 제거·재시작 보존·키 폐기·산출물 저장을 연결해 시험한다. 실제 사이버공격 탐지, 외부 webhook 인증과 수집기 상시 배치 완료를 뜻하지 않는다. 해당 도구와 운영 신원 연동은 각 어댑터의 별도 자격이다.
