# 배포 차단 해소와 플랫폼 인수 후속 작업

시작: 2026-11-06 16:23 UTC / 11-07 01:23 KST. 최대 5시간, 완료 시 조기 종료.
기준 플랫폼: `42811da4cf19ce941491d4794ab49790881dc409`.
수정 범위: security·sova-test. 실제 팀 플랫폼 배포와 개인 환경 검증은 구분한다.

## 요구사항과 완료 기준

- IMG-01: 기존 HIGH 49건의 원인을 제거한 이미지로 전체 OS/Python 재스캔.
  HIGH/CRITICAL 차단, UNKNOWN 보류, 실제 설치 목록 대조를 유지한다.
- OPS-01: 실제 지정 플랫폼의 인증·권한·네트워크·감사·복구 동작을 검증한다.
  테스트 계정·클러스터·namespace가 확인되지 않은 상태에서 임의 운영 변경하지 않는다.
- T28-01: 효과 전 영속 접수, 중단 후 재호출 금지, 별도 조회·조정 경계 검증.
  기존 T10/T31 및 Sova 실행 원장을 재사용하고 승인 체계를 중복하지 않는다.

## 이미지 후보 설계 (구현, 검증 전)

기존 Debian 13 이미지의 HIGH 49건은 13개 CVE의 패키지별 발생 수다.
Debian tracker는 CVE-2026-76642의 trixie를 여전히 vulnerable로 표시한다.
https://security-tracker.debian.org/tracker/CVE-2026-76642

공식 Python 3.12.16 Alpine 3.24 후보의 registry index digest를 조회했다:
`sha256:e064671ca452259bab50e8e2c7bd896e39e9a343bb06ca25234adf6fe18d0fc7`.
linux/amd64 manifest: `sha256:a61cbd76a882645de7f91423329fe43a67eed60d7da24f9e5331414bb3618b20`.
공식 소스 revision `3d7e95597e56a415d9e4abc0f15877e005d2cb2e`, 2026-11-05 생성.
https://hub.docker.com/_/python

glibc에서 musl로 바뀌므로 단순 스캔만으로 채택하지 않는다. 기존 lock의 binary wheel만 설치하며
실제 컨테이너 TLS·PostgreSQL·T10 연결·철회 시험을 모두 수행한다. APK 설치 DB를 보존하고
실제 package name/version/architecture와 scanner 결과의 정확한 일치를 요구한다.
기존 Debian 증거 재검증도 유지하고, 지원하지 않는 라이브러리 종류를 조용히 무시하지 않는다.
아직 후보이며 PASS나 배포 허가를 주장하지 않는다.

## 환경 확인

Windows에 Kubernetes context가 없고 기존 AWS default 계정은 플랫폼용인지 확인되지 않았다.
WSL에는 AWS 설정이 있지만 kubeconfig가 없다. 사용자에게 시험 대상과 profile/namespace를
문의했다. 비밀 값은 요청하지 않았다. 이 확인을 기다리는 동안 IMG-01/T28-01을 진행한다.
로컬 공간이 약 1.8 GiB이므로 대형 이미지/취약점 DB는 내려받지 않고 격리된 Linux CI를 사용한다.

## 검증 기록

아래에 커밋별 명령·결과·실패와 해결·증거 위치를 추가한다. 운영 인수는 아직 미검증이다.

- IMG-01: `python -m pytest -q tests/contracts/test_service_image_scan.py`: **48 PASS**。
  Alpine의 잘못된 릴리스·아키텍처·OS 종류·버전·누락된 inventory와 미지원 scanner category를
  거부하고, 미수정 HIGH는 계속 BLOCK임을 검증했다. 최초 lint의 import 순서 오류를 수정했다.
  실제 이미지 빌드·런타임·스캔은 이 커밋의 원격 CI 결과를 기다린다.

- IMG-01 완료 근거: source `338f755`, CI `42252529744`에서 **전체 심각도 0건, PASS**.
  실제 OS 38/Python 10 대조, PG 58·HBA 1·이미지/T10 11 PASS.
  [원본과 공급망 대조](../evidence/service-image-scan-2026-11-07/qualified-338f755/README.md).
  registry 발행·ARM64·운영 인수는 아직 별도다.
- T28-01: sova-test `31fc071`에 기존 effect journal 연결을 구현했다.
  최신 42811da 실제 T28 원문과 자식 프로세스 강제 종료/경쟁을 포함해 **24 PASS / 2.81초**.
  플랫폼 직접 실행 entrypoint의 권한 제한과 실제 T10/운영 adapter 주입은 아직 인수 전이다.
- COMPAT-10: 기본 플랫폼을 42811da로 이동하고 앞선 9개 기준을 유지하는 열 번째 소비 시험을 추가했다.
  로컬 focused 시험은 C: 공간이 1.5 GiB 아래로 내려가 용량 guard에서 중단됐으며 성공으로 세지 않았다.
  대형 다운로드·추가 WSL 실행을 중단하고 원격 CI에서 검증한다. 다른 사용자 프로세스/파일은 건드리지 않았다.
- OPS-01: 최신 팀 self-service는 kubeconfig 배포 대신 본인 Tailscale 로그인과 비밀 없는
  `team-test.json`을 사용한다. 기존 T7 직접 API·단기 토큰을 우선 재사용한다.
  실제 RKE2 시험 기록은 ARM64이므로 amd64 이미지 성공을 해당 배포 성공으로 간주하지 않는다.

## ARM64 인수 준비 (IMG-02)

실제 플랫폼의 RKE2/ARM64 기록을 확인해 이미지 검증을 native ARM64에도 확장한다.
GitHub의 `ubuntu-24.04-arm` runner를 사용하며 QEMU 성능 결과로 대체하지 않는다.
https://docs.github.com/en/actions/reference/runners/github-hosted-runners

빌드 manifest·실제 컨테이너 CPU·Docker inspect·Trivy ImageConfig·OS 패키지 arch가
모두 같아야 한다. amd64와 arm64 artifact를 구분하고 각각 기존 PG/TLS/T10/철회 시험을 실행한다.
공식 Trivy 0.76.2 ARM64 archive의 공개 digest를 확인한 뒤 메모리에서만 hash를 대조했다.
archive `ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3`,
binary `7844c3851b28470b6d7f0975fa0b3262c5b2272c9a54a91f522801bb8926f51f`를 고정한다.
https://github.com/aquasecurity/trivy/releases/tag/v0.76.2

로컬 계약 시험 **53 PASS / 0.14초**, lint 성공. ARM64 실제 빌드 결과는 아직 검증 전이다.
이 추가 작업은 플랫폼 노드 아키텍처와의 호환성을 확인하기 위한 것으로 운영 배포를 수행하지 않는다.

- IMG-02 결과: `865e484`, [CI 42254592499](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42254592499)
  **성공**. native amd64·arm64 모두 스캔 PASS, ARM64 PG 58·HBA 1·실제 이미지/T10 11 PASS.
  최신 42811da를 포함한 10개 platform 계약 job도 성공했다.
- T28 PostgreSQL 결과: sova-test `6e000ff`,
  [CI 42255522327](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42255522327) 성공.
  실제 lease/승인/복구 원장과 합성 파일 효과를 연결했다. 플랫폼 운영 적용으로 집계하지 않는다.

## 검사한 이미지 자체 보존 (IMG-03)

이전 artifact는 재빌드 입력과 scan을 보존했지만 실제 image layer는 보존하지 않았다.
같은 source에서 재빌드해도 생성 시각 등으로 config ID가 달라질 수 있어, 검사한 정확한 이미지를
`docker save` gzip artifact로 별도 보존한다. 최근 30분 이내 동일 source/platform/config ID의
policy PASS만 export한다. BLOCK/UNKNOWN이면 수집 원본은 남기되 export와 job은 실패한다.
archive SHA-256·scan decision hash를 붙이고 arch별로 구분한다. registry에는 push하지 않는다.
다운로드·배포 전 기존 플랫폼 발행/서명/승인 경로가 여전히 필요하다.
해시만으로 발행자 신뢰나 실행 권한을 주장하지 않는다.

로컬 관련 계약 시험 **63 PASS / 0.15초**, lint 성공. CI의 실제 archive 생성은 후속 검증한다.
