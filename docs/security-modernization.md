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
