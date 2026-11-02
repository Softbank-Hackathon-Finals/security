# Prowler 구성 점검 보고서 연결

Prowler의 클라우드 점검 기능을 다시 구현하지 않는다. 등록된 수집기가 만든 OCSF 보고서를 제한된 자원·점검 항목의 구성 근거로 받아들인다. 첫 프로필은 Prowler 5.47.0의 AWS 출력이며, 실행 중인 자원의 접근 거부나 데이터 보호를 직접 시험한 결과와 구분한다.

## 신뢰 경계

1. 운영자가 `ConfigurationScanRegistration`에 앱 범위, 현재 revision, AWS 계정·리전·자원 ARN, 예상 점검 ID, 수집 허용 시간을 등록한다.
2. 별도 수집기가 Prowler를 실행하고 원본 보고서를 승인된 저장소에 보관한다. 실행 권한·수집 completeness·수집기 운영은 호출 서비스 책임이다.
3. 등록된 독립 수집 검증기가 원본 보고서 해시와 등록 fingerprint를 `EvidenceRecord`에 묶어 서명한다. 검증 버전은 `sova.prowler.collector.v1`, 의무 ID는 `prowler-collection:<registration fingerprint>`다.
4. `ConfigurationAssessmentService.collect`가 사용자 권한, 등록·수집 영수증의 인증과 기한, 원본 해시 및 revision을 확인한다. 외부 보고서가 스스로 주장하는 계정이나 버전만으로 신뢰하지 않는다.
5. 등록된 입력이 바뀌지 않았는지 다시 확인하고, 구성 snapshot을 보안 소유 원장에 저장한 뒤 readback을 확인한다. 검사 중 권한 회수·서명 신뢰 변경·만료는 성공 응답을 막는다.

기본 변환 함수 `prowler_configuration` 자체는 서명을 검증하지 않는다. 인증된 서비스 경계를 거치지 않은 변환 결과를 실행 근거로 쓰면 안 된다. 서명·승인·클라우드 자격증명을 보고서 JSON의 문자열로 대체하지 않는다.

## 결과 해석

Prowler OCSF의 `status_id`·`status`는 finding의 수명주기 상태다. PASS/FAIL은 `status_code`에 있다. 억제된 finding, 인식하지 못한 상태, 수동 확인·오류·누락은 UNKNOWN으로 남긴다. 빈 보고서는 성공이 아니다.

한 보고서는 등록한 자원 하나와 예상 점검 최대 128개만 포함한다. 다른 계정·리전·자원, 중복 점검, 버전 변경, 미래·오래된 관측, 중복 JSON 필드와 과대 입력은 거부한다. 보고서 시간은 공식 구현의 Unix **초** 단위이며, 최대 신선도는 5분이다. 광범위한 계정 전체 보고서를 무단 필터링해 앱 보고서로 승격하지 않는다. 필요한 경우 수집기가 명시적 범위의 원본 산출물을 별도로 만들고 그 해시를 서명해야 한다.

`all_selected_checks_pass`는 선택한 구성 항목의 성공만 뜻한다. `configuration_evidence`가 만드는 서명 전 근거는 `sova.prowler.configuration.v1`과 `prowler-configuration:<check ID>`를 사용한다. TLS 강제·다른 테넌트 접근 거부·백업 복구·실제 네트워크 도달성 등의 런타임 의무를 이 버전으로 충족시킬 수 없다. 팀의 통제 ID와 연결하는 표는 팀 정책 소유자가 별도로 확정한다.

## 검증과 한계

공식 출력 구현과 fixture를 대조한 합성 입력으로 정상·FAIL·누락·억제·범위 불일치·재바인딩·서명 거부·늦은 권한 회수를 시험한다. 이는 **실계정 Prowler 스캔 완료나 전체 CIS·규제 준수 인증을 뜻하지 않는다.** 실제 수집기의 IAM 권한, 보고서 발급 서명과 독립 운영 경계는 배치 환경에서 추가 자격 시험이 필요하다.

공식 출처:

- [Prowler 5.47.0 OCSF 출력 구현](https://github.com/prowler-cloud/prowler/blob/5.47.0/prowler/lib/outputs/ocsf/ocsf.py)
- [Prowler 5.47.0 OCSF 시험](https://github.com/prowler-cloud/prowler/blob/5.47.0/tests/lib/outputs/ocsf/ocsf_test.py)

이 문서는 운영 통합 계약이다. 개발 중 시험 결과와 비공개 실행 기록은 저장소에 포함하지 않는다.
