# 검증한 wheel 소비

패키지 버전은 PyPI에 게시했다는 뜻이 아니다. 다른 프로젝트는 `security` 저장소를 직접 빌드하거나, main CI가 남긴 특정 커밋의 wheel을 사용한다. Sova 전체를 복사할 필요는 없다.

## CI 산출물

main push의 Python 3.11 작업은 시험·정적 검사 후 wheel을 빌드하고 다음 네 파일을 업로드한다. PR에서는 소비용 산출물을 게시하지 않는다. Python 3.14 작업도 별도로 같은 코드의 호환성을 시험한다.

- `sova_security-<version>-py3-none-any.whl`
- `manifest.json`: 저장소·전체 commit SHA·workflow·run·버전·wheel 해시
- `dependencies.json`: 시험 환경에서 실제 설치된 패키지명·버전
- `SHA256SUMS`: wheel과 dependencies.json의 해시

산출물 이름은 `sova-security-wheel-<전체 commit SHA>`이며 보존 기간은 30일이다. 설치 전에 **전체 워크플로의 두 Python 작업과 secrets 작업이 모두 성공했는지** 확인한다. 3.11 산출물이 존재한다는 사실만으로 아직 실행 중이거나 실패한 3.14 작업이 통과한 것은 아니다.

```sh
gh run view RUN_ID --repo Softbank-Hackathon-Finals/security
gh run download RUN_ID --repo Softbank-Hackathon-Finals/security \
  --name sova-security-wheel-FULL_COMMIT_SHA --dir ./security-wheel
cd security-wheel
# macOS
shasum -a 256 -c SHA256SUMS
# Linux에서는 sha256sum -c SHA256SUMS
```

`manifest.json`의 저장소·commit SHA·run ID·package version이 선택한 CI와 일치하는지도 확인한다. 확인한 wheel 파일과 manifest는 소비 프로젝트의 승인된 아티팩트 저장소에 함께 보관한다. 만료 후 다른 커밋의 동명 버전을 대신 내려받지 않는다.

설치는 실제 파일명을 사용한다. 필요한 기능만 extra로 선택한다.

```sh
python -m pip install './sova_security-<version>-py3-none-any.whl[postgres,signing,team]'
```

기본 설치는 클라우드 SDK·DB 연결 없이 사용할 수 있다. `aws` extra와 클라우드 권한은 실제 AWS 수집기가 필요한 소비자만 준비한다. 의존 버전의 보안 점검과 설치 환경의 잠금도 소비 프로젝트 책임이다.

## 로컬 빌드

검토한 commit을 checkout한 `security` 저장소에서 다음 명령으로 빌드할 수 있다.

```sh
python -m pip wheel . --no-deps --no-build-isolation -w ./dist
```

이 명령에는 프로젝트의 build-system 요구를 만족하는 setuptools가 필요하다. 로컬 산출물과 CI 산출물은 별개로 식별하고 해시를 기록한다. 서로 다른 빌드 환경에서 wheel 바이트가 항상 같다고 가정하지 않는다.

## 보증의 범위

체크섬은 전송 중 변경을 확인한다. manifest 단독으로 발행자의 진위를 증명하지 않는다. 신뢰 경계는 선택한 저장소·검토한 commit·성공한 GitHub Actions 실행 및 그 실행에 묶인 산출물이다. 이 경로를 Sigstore 서명, SLSA 인증 또는 장기 지원용 정식 릴리스라고 부르지 않는다. 장기 배포에는 별도 패키지 저장소·발행 정책·보존 및 서명 검증을 연결해야 한다.

보안 입력·리허설의 Ed25519 서명은 운영 근거 인증이며, 이 wheel의 공급망 서명과는 다른 책임이다. 어느 한쪽으로 다른 쪽 검증을 대신하지 않는다.


## 잠긴 CI 의존성

CI는 SHA로 고정한 공식 setup-uv v9.0.0과 uv 0.13.6을 사용한다. `uv.lock`은 Python·운영체제별 조건을 포함한 정확한 배포 버전과 해시를 기록한다. `uv sync --locked --extra dev --no-install-project --no-build`로 잠금 변경을 거부하고, 외부 의존성은 wheel만 설치한다. 이후 현재 저장소만 네트워크 없이 설치·빌드한다. CI는 Python 3.11·3.14를 각각 명시한다.

개발 extra의 pip 26.2.2와 setuptools도 이 잠금에 포함한다. manifest는 `uv.lock`의 SHA-256과 실제 설치 목록의 해시를 묶는다. 기본 사용자 설치의 dependency 범위와 CI 환경 잠금은 서로 다른 계약이다. 소비 서비스는 자신의 Python·OS·extra에 맞는 잠금을 따로 관리한다.

의도한 의존 변경은 uv 0.13.6에서 `uv lock --upgrade-package PACKAGE`로 갱신하고 전체 diff·공개 취약점·두 Python CI를 검토한다. pyproject의 extra·빌드 요구 변경도 함께 반영한다. 잠금 파일을 수작업으로 고치거나 실패한 lock 검사를 `--frozen`으로 우회하지 않는다. 해시 고정은 출처가 승인된 패키지의 악성 동작까지 방지하지 않는다.

공식 근거: [uv universal lockfile](https://docs.astral.sh/uv/concepts/projects/layout/#the-lockfile), [GitHub Actions 통합](https://docs.astral.sh/uv/guides/integration/github/).

`secrets` 작업은 고정 Gitleaks 8.30.1로 전체 Git 이력을 검사한다. 출력은 마스킹하며 보고서를 소비 artifact에 포함하지 않는다. checkout 자격증명을 Git 설정에 남기지 않는다. 탐지 없음이 키 부재나 유출 부재 전체를 보증하지 않으며, 탐지 시에는 해당 자격증명을 먼저 철회하고 이력·운영 영향을 검토한다. 승인 없는 검사 예외나 실패 무시는 추가하지 않는다.
