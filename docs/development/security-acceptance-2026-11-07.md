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
