# Sova Security

Team Bravo 플랫폼 연동을 위해 개인 환경에서 검증하는 공통 Python 보안 패키지와 선택형 보안 판정 서비스다. 보호 수준 비교, 근거 검증, 보안 보류와 제한된 대응 계획을 제공한다. **보안 판정은 사용자 승인이나 운영 실행 권한을 부여하지 않는다.**

두 보안 문서 적용 결과와 플랫폼 연결 순서는 [인계 현황](docs/platform-handoff-status.md)에서 확인한다.

## 현재 포함 범위

- 통제·보류·해제, 보호 목적 비교와 실행 전 게이트
- 서명 근거·검증기 신뢰·기한·revision 검증
- 보류 해제 승인 전체 서명과 별도 사고 이후 재검증
- 자산·스캔·정책·리허설 요청의 입력 종류별 서명 인증
- AI 데이터 위치 정책 판정과 제한된 호출 경계
- Kubernetes 구성 해석·AWS RDS 읽기 전용 조사 어댑터
- 보안 snapshot/event, 제한된 무상태 대응 계획과 완료 영수증
- Prowler OCSF의 서명된 수집 결과와 구성 점검 근거 연결
- Trivy·CycloneDX 보고서 연결, 위험 평가·패치 리허설·실행 후 재평가
- CISA KEV의 서명된 양성 일치와 검토 후보 생성
- Harbor 요청·독립 서명 검증, 기존 승인·실행기에 연결할 패치 guard
- 지속 재평가와 변경 감지에 따른 보안 보류
- 고정 OPA 실행기·Rego 정책과 기존 실행 전 검증의 교집합
- 팀 T5 ControlRun 계약의 등록·서명 수용, 기존 보호 수준 비교 연결
- 테넌트 제한 PostgreSQL 어댑터와 보안 소유 SQL 7개
- 두 보안 설계 문서의 CTRL-01~09 · POL-01~12 · SEC-PATCH-01~10을 연결한 패치/이전 검사 프로필과 사전·사후 검증
- 기존 생산자 원본 서명·최신 관측과 프로그램 증거 연결, PostgreSQL 등록·철회 및 Sova 패치 실행 조합
- 현재 워크로드 인증·테넌트 전용 읽기 권한·TLS 판정 서비스, 병행 비교와 T10/Sova 소비 어댑터

Sova의 실행 원장·승인 서비스·작업 큐·격리 실행 조정기·시험용 클러스터 어댑터·전체 콘솔·데모 앱은 포함하지 않는다. Sova는 이 패키지를 사용하는 첫 통합 시험 환경이다. 팀 platform 연결과 일반 고객 환경의 운영 자격은 별도 검증 대상이다.

## 설치

Python 3.11 이상을 사용한다. 기본 설치에는 클라우드 SDK나 DB 연결이 필요 없다.

```sh
python -m pip install /path/to/sova_security-0.11.0-py3-none-any.whl
# 개발 시 이 저장소에서
python -m pip install -e '.[dev]'
python -m pytest -q
ruff check src tests
```

PostgreSQL 어댑터는 `postgres`, 서명은 `signing`, AWS 시험·사용은 `aws`, 팀 JSON Schema 연결은 `team`, CISA KEV 연결은 `intelligence` extra를 설치한다. AWS 클라이언트와 자격증명은 호출자가 제공한다. import나 설치만으로 자원을 생성하거나 SQL을 실행하지 않는다.

Sova에서 로컬 개발 연결:

```sh
cd /path/to/sova
.local-notes/venv/bin/python -m pip install -e '../team-bravo/security[postgres,signing,aws]'
```

릴리스 소비 환경은 검증한 wheel과 해시를 고정한다. [CI 산출물 소비 방법](docs/distribution.md)을 따른다. 0.11.0은 0.10.0의 두 문서 통합 계약에 선택형 서비스를 추가하며 PyPI 배포를 뜻하지 않는다.

서비스 실행은 `service` extra와 [설정·신뢰 경계·배포·인수 안내](docs/security-review-service.md)를 따른다. platform 고정 SHA의 소비 시험은 Python 3.12 이상에서 `dev,platform-test` extra로 수행한다. 기본 패키지 설치는 서비스를 자동 시작하지 않는다.

두 문서의 원문·요구사항 추적·구현 경계는 [보안 설계 통합](docs/architecture-integration.md), 실제 `platform` 연결 순서는 Sova의 [인계 문서](../sova-test/docs/platform-security-handoff.md)를 참고한다. 카탈로그에 검사가 있다는 사실은 해당 환경의 통과 근거가 아니다.

현재 저장소·서명 증거·실행기를 연결하는 코드는 [생산자 연결과 호스트 조합](docs/program-evidence-integration.md)에 있다. 기존 팀 ControlRun과 강화된 2026-11-06 schema snapshot을 명시적으로 선택할 수 있다.

## 통합 계약

`sova_security.contracts`는 현재 추출 기준의 v1 경계 타입을 제공한다. 범위·revision·근거·불변 계획과 저장소 오류 타입만 공유하며, 실행 엔진이나 승인 권한은 포함하지 않는다. 팀 공통 계약이 이미 다르면 명시적 변환 어댑터로 연결해야 한다. 이름이 같은 dataclass를 다시 정의해 혼용하지 않는다.

주요 모듈은 `domain`, `application`, `ports`, `adapters`다. `ProtectionParityGuard`와 `GovernanceGuard`에는 신뢰된 정책·현재 revision·근거 인증·보류 조회·시계를 제공한다. 패키지가 브라우저 입력을 신뢰된 사용자·조직 권한으로 승격하지 않는다.

[보류 해제 서명 연결](docs/hold-release-signatures.md), [악용 취약점 목록 연결](docs/exploitation-intelligence.md), [평가 입력 서명 연결](docs/assessment-input-signatures.md), [팀 통제 결과 연결](docs/team-control-integration.md), [Prowler 보고서 계약](docs/prowler-integration.md), [OPA 통합 계약](docs/opa-policy.md)과 [Harbor 담당 경계](docs/harbor-contract.md)를 제공한다.

[지속 보안 개선 계약](docs/security-modernization.md)은 자산·위험·Harbor·패치 승인 연결과 검증 한계를 설명한다. 실제 Harbor 실행기, 이미지 교체 adapter, 기업 인증과 고객 환경 운영 자격은 포함하지 않는다.

PostgreSQL은 현재 `sova_control` 스키마와 `sova.tenant_id` 컨텍스트를 사용하는 추출 프로필이다. 스키마 이름이 범용화되거나 별도 DB 권한 도메인으로 검증됐다는 뜻이 아니다. [저장소와 마이그레이션 경계](docs/integration.md)를 따른다.

## 검증과 출처

기존 Sova의 검증된 코드와 테스트를 추출했다. [원본 커밋·파일 해시](docs/provenance.json)를 제공한다. 패키지 시험과 Sova 전체 통합 회귀는 구분하며, 테스트 더블을 실제 AWS·Kubernetes 검증으로 표현하지 않는다. 비밀을 제외한 [개발 기록](docs/development/security-service-2026-11-06.md)을 유지하며 인증정보·개인 실행 상태는 게시하지 않는다.

팀 T33 탐지 계약은 [탐지 연결 안내](docs/detection-integration.md)를 따른다. 정확한 자원 매핑·등록과 수집 출처 인증을 요구하며, 탐지 데이터가 변경·격리 권한을 직접 부여하지 않는다.
