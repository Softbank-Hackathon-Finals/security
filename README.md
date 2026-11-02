# Sova Security

Team Bravo 플랫폼에 설치하는 Python 보안 패키지다. 보호 수준 비교, 근거 검증, 보안 보류와 제한된 대응 계획을 제공한다. **보안 판정은 사용자 승인이나 운영 실행 권한을 부여하지 않는다.**

## 현재 포함 범위

- 통제·보류·해제, 보호 목적 비교와 실행 전 게이트
- 서명 근거·검증기 신뢰·기한·revision 검증
- AI 데이터 위치 정책 판정과 제한된 호출 경계
- Kubernetes 구성 해석·AWS RDS 읽기 전용 조사 어댑터
- 보안 snapshot/event, 제한된 무상태 대응 계획과 완료 영수증
- Prowler OCSF의 서명된 수집 결과와 구성 점검 근거 연결
- Trivy·CycloneDX 보고서 연결, 위험 평가·패치 리허설·실행 후 재평가
- Harbor 요청·독립 서명 검증, 기존 승인·실행기에 연결할 패치 guard
- 지속 재평가와 변경 감지에 따른 보안 보류
- 고정 OPA 실행기·Rego 정책과 기존 실행 전 검증의 교집합
- 테넌트 제한 PostgreSQL 어댑터와 보안 소유 SQL 7개

Sova의 실행 원장·승인 서비스·작업 큐·격리 실행 조정기·시험용 클러스터 어댑터·전체 콘솔·데모 앱은 포함하지 않는다. Sova는 이 패키지를 사용하는 첫 통합 시험 환경이다. 팀 platform 연결과 일반 고객 환경의 운영 자격은 별도 검증 대상이다.

## 설치

Python 3.11 이상을 사용한다. 기본 설치에는 클라우드 SDK나 DB 연결이 필요 없다.

```sh
python -m pip install /path/to/sova_security-0.4.0-py3-none-any.whl
# 개발 시 이 저장소에서
python -m pip install -e '.[dev]'
python -m pytest -q
ruff check src tests
```

PostgreSQL 어댑터는 `postgres`, 서명은 `signing`, AWS 시험·사용은 `aws` extra를 설치한다. AWS 클라이언트와 자격증명은 호출자가 제공한다. import나 설치만으로 자원을 생성하거나 SQL을 실행하지 않는다.

Sova에서 로컬 개발 연결:

```sh
cd /path/to/sova
.local-notes/venv/bin/python -m pip install -e '../team-bravo/security[postgres,signing,aws]'
```

릴리스 소비 환경은 검증한 wheel과 해시를 고정한다. 현재 0.4.0은 최초 추출 이후 보안 개선 계약을 추가한 버전이며 PyPI 배포를 뜻하지 않는다.

## 통합 계약

`sova_security.contracts`는 현재 추출 기준의 v1 경계 타입을 제공한다. 범위·revision·근거·불변 계획과 저장소 오류 타입만 공유하며, 실행 엔진이나 승인 권한은 포함하지 않는다. 팀 공통 계약이 이미 다르면 명시적 변환 어댑터로 연결해야 한다. 이름이 같은 dataclass를 다시 정의해 혼용하지 않는다.

주요 모듈은 `domain`, `application`, `ports`, `adapters`다. `ProtectionParityGuard`와 `GovernanceGuard`에는 신뢰된 정책·현재 revision·근거 인증·보류 조회·시계를 제공한다. 패키지가 브라우저 입력을 신뢰된 사용자·조직 권한으로 승격하지 않는다.

[Prowler 보고서 계약](docs/prowler-integration.md), [OPA 통합 계약](docs/opa-policy.md)과 [Harbor 담당 경계](docs/harbor-contract.md)를 제공한다.

[지속 보안 개선 계약](docs/security-modernization.md)은 자산·위험·Harbor·패치 승인 연결과 검증 한계를 설명한다. 실제 Harbor 실행기, 이미지 교체 adapter, 기업 인증과 고객 환경 운영 자격은 포함하지 않는다.

PostgreSQL은 현재 `sova_control` 스키마와 `sova.tenant_id` 컨텍스트를 사용하는 추출 프로필이다. 스키마 이름이 범용화되거나 별도 DB 권한 도메인으로 검증됐다는 뜻이 아니다. [저장소와 마이그레이션 경계](docs/integration.md)를 따른다.

## 검증과 출처

기존 Sova의 검증된 코드와 테스트를 추출했다. [원본 커밋·파일 해시](docs/provenance.json)를 제공한다. 패키지 시험과 Sova 전체 통합 회귀는 구분하며, 테스트 더블을 실제 AWS·Kubernetes 검증으로 표현하지 않는다. 개발기록·인증정보·실행 상태는 게시하지 않는다.
