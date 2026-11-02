# 팀 통제 결과와 보안 패키지 연결

팀 플랫폼의 통제 결과 계약을 그대로 수용하되, 실행 권한과 검증 신뢰는 기존 경계로 유지한다. 플랫폼의 T5·T14·T19 작업을 이 문서나 변환 코드만으로 완료 처리하지 않는다. 실제 통제 시험 실행기와 플랫폼 API 연결은 별도다.

## 기준 계약

팀 `platform`의 커밋 `fc5a25e46904f55908da8bdee7122e4ad1574c5f`에 있는 `docs/controls/control-result.schema.json`을 수정 없이 패키지에 포함한다. SHA-256은 `7c9728028af9c9d8bc45f5e8a8ba2b3ba0e38c96b7373b7338b49c8f37adfeb9`이다. 출처와 원본 해시는 패키지 `schemas/provenance.json`에 기록한다.

JSON Schema 2020-12 검증은 기존 `jsonschema` 라이브러리를 사용한다. 날짜 형식 검증만 필요하므로 `team` extra는 `jsonschema`와 `rfc3339-validator`를 설치한다. 새 스키마 엔진이나 명령 실행기를 만들지 않는다. 스키마의 로컬 `$defs`만 사용하며 외부 참조를 가져오지 않는다.

## 처리 순서

```text
등록된 앱·환경·자원·revision·시험 방법
  → 서명된 원본 ControlRun 수집 영수증 확인
  → 고정 JSON Schema 검증
  → 기대 결과·대조군·방법·시각·중복·범위 검사
  → 보안 소유 원장 저장 및 readback
  → 명시적 정책 매핑
  → 독립 검증기의 변환 후 근거 서명
  → 기존 보호 수준 비교·보류·실행 전 게이트
```

`TeamControlRegistration`에는 예상 시험별 방법 버전·기대 결과·대조군 의무, 환경 참조와 역할, 최대 근거 연령을 등록한다. 스키마 해시도 등록 fingerprint의 일부다. 보고서가 이 등록 내용을 바꿀 수 없다.

`TeamControlRunService`는 인증된 등록·현재 보고서 공급자·사용자 권한·보안 원장을 주입받는다. 원본 영수증은 `team-bravo.controls.collector.v1` 검증기, `team-control-collection:<등록 fingerprint>` 의무, 정확한 원본 해시와 revision을 포함해야 한다. 기존 `SignedEvidenceAuthority`와 등록된 검증기 신뢰로 인증한다. 문자열 `PASS`나 보고서 안의 선택적 signature 필드만으로 인증하지 않는다. 신뢰 콜백에 기본 허용 구현을 넣지 않는다.

수집 영수증은 출처와 원본의 결합을 증명한다. 실제 시험 방법이 올바르다는 것은 시험기 자격과 독립 검증으로 별도 확인해야 한다. 에이전트가 수집기·검증기 키를 가지면 이 경계가 성립하지 않는다.

## 실패와 미검증

| 입력 | 처리 |
| --- | --- |
| 등록한 앱·환경·자원·revision과 다른 보고서 | 거부 |
| 중복 시험 ID, 통제 ID 오표기, 기대 결과 변조 | 거부 |
| PASS인데 관측 결과가 기대 결과와 다름 | 거부 |
| 거부 시험의 정상 대조군 성공이 없음 | UNKNOWN |
| 시험 방법 버전이 등록값과 다름 | UNKNOWN |
| 근거 만료·최대 연령 초과·시험 누락 | UNKNOWN |
| GateComparison의 PASS 입력 | 수용하지 않음; 실행 권한으로 사용 불가 |
| 검사·저장 중 등록 변경·권한 회수·서명 신뢰 변경 | 성공 응답 차단 |

UNKNOWN을 현재 시각에 기록하는 경우, 새로 확인한 사실은 **미검증 사유**다. 오래된 PASS의 유효기간을 연장하는 것이 아니다. 명령·출력 발췌·artifact URI는 변환 산출물에 복사하거나 실행·조회하지 않는다. 원문은 별도의 승인된 저장소에 두고 해시만 연결한다.

## 기존 비교기로 연결

`parity_record`는 정책에 `requirement_id = team-control:<시험 ID>`가 명시된 경우에만 변환한다. 등록된 양쪽 scope·revision·방법 버전이 일치해야 한다. 출발지와 목적지의 역할을 바꾸어 끼울 수 없다. 원래 수집 서명을 변환 후 다른 payload에 재사용하지 않고, 독립 검증기가 그 근거를 다시 서명한다.

비교 자체는 기존 `assess_protection`과 `ProtectionParityGuard`가 수행한다. 예외 승인이나 별도 보류 boolean을 새로 만들지 않는다. 방법이 다른 두 PASS도 동등성으로 처리하지 않는다. 소스·대상 모두 불충분한 기준인 경우 이를 복제해서 합격시키지 않도록 기존 필수 보호 프로필도 함께 적용해야 한다.

## 검증 한계

원본 팀 예시 JSON을 입력으로 하는 형식·의미 검사, 보호 수준 비교 연결, PostgreSQL 범위 격리·저장·폐기를 시험한다. 예시 데이터는 합성 자료이며 실제 AWS·RKE2 통제 시험의 성공을 뜻하지 않는다. 팀의 여섯 통제에 해당하는 모든 실제 probe, T19의 전체 데이터 컷오버 게이트, 콘솔 연결은 이 어댑터만으로 완성되지 않는다.

출처:

- [팀 통제 계약 원본](https://github.com/Softbank-Hackathon-Finals/platform/blob/fc5a25e46904f55908da8bdee7122e4ad1574c5f/docs/controls/control-result.schema.json)
- [팀 통제 시험 의미와 판정 규칙](https://github.com/Softbank-Hackathon-Finals/platform/blob/fc5a25e46904f55908da8bdee7122e4ad1574c5f/docs/controls/README.md)
- [jsonschema 검증 API](https://python-jsonschema.readthedocs.io/en/stable/validate/)
