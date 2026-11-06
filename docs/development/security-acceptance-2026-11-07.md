# 배포 차단 해소와 플랫폼 인수 후속 작업

시작: 2026-11-06 16:23 UTC / 11-07 01:23 KST. 최대 5시간, 완료 시 조기 종료.
시작 시 기준 플랫폼: `42811da4cf19ce941491d4794ab49790881dc409`.
수정 범위: security·sova-test. 실제 팀 플랫폼 배포와 개인 환경 검증은 구분한다.

최신 코드 인계 기준은 producer `546f6e0482cc06fa32f00ea8d554522551a84beb`, platform develop
`0795f65e24f58e43545b16b97757efcc0923fd4a`, 발행 host source `445848d2ed9878e31eb6f5aabad0575c61739b47`이다.
최종 producer CI `42265872242`는 12개 계약·Python·native 양쪽 이미지를 모두 통과했다.
아래 초기 후보/접속 미확인 문단은 작업 당시의 이력이며, 최종 상태는 인계 문서와 후속 결과를 따른다.
OPS-01은 사용자의 후속 지시로 데모용 맥의 실제 로그인·검증에 넘기고, 이번 범위에서는
SSO/SSM·platform-state 읽기 전용 범위와 인수 조건을 준비한다. 실환경 PASS로 표시하지 않는다.

## 요구사항과 완료 기준

- IMG-01: 기존 HIGH 49건의 원인을 제거한 이미지로 전체 OS/Python 재스캔.
  HIGH/CRITICAL 차단, UNKNOWN 보류, 실제 설치 목록 대조를 유지한다.
- OPS-01: 실제 지정 플랫폼의 인증·권한·네트워크·감사·복구 동작을 검증한다.
  테스트 계정·클러스터·namespace가 확인되지 않은 상태에서 임의 운영 변경하지 않는다.
- T28-01: 효과 전 영속 접수, 중단 후 재호출 금지, 별도 조회·조정 경계 검증.
  기존 T10/T31 및 Sova 실행 원장을 재사용하고 승인 체계를 중복하지 않는다.

## 초기 이미지 후보 설계 (당시 구현, 검증 전)

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

## 초기 환경 확인

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

archive export 뒤에는 Docker load와 network-none/read-only 컨테이너 재검증을 실행해
원래 runtime inventory와 바이트 단위로 대조한다. 큰 이미지 artifact를 받지 않고도 검토할 수 있도록
작은 입력 artifact에 archive provenance를 함께 보존한다. CI 외부 registry나 운영 환경은 변경하지 않는다.

## libc 변경 후 컨테이너 지속 검증 (IMG-04)

기존 3시간 시험은 호스트 Python 프로세스였다. 새 Alpine/musl 이미지의 지속 동작 증거로
대체할 수 없으므로 native amd64·arm64 컨테이너 각각 90분 시험을 추가한다.
기존 PG/TLS/합성 issuer·서명 원본 fixture와 회전/철회/만료 시나리오를 재사용한다.
컨테이너 안의 PID 1이 실제 review_server인지 확인하고 그 프로세스의 RSS/FD/thread를 측정한다.
Docker CLI 프로세스의 자원을 서비스 자원으로 잘못 기록하지 않는다.
종료 후 소유 컨테이너 부재와 CLI child 종료를 모두 확인한다.

`[image-endurance-90m]`가 포함된 개인 브랜치 push만 90분 시험을 실행한다.
일반 push/PR은 장시간 실행하지 않는다. 원본 보고서에 image config ID, source, architecture,
시험·harness hash, 실제 경과 시간과 자원 범위를 남긴다. 운영 부하·CNI 검증은 아니다.

첫 IMG-04 CI `42257008812`는 package boundary 검사에서 중단됐다. Python 표준 라이브러리
`platform` import가 팀 저장소 `platform` 의존 금지 규칙과 이름이 겹쳤다. 검사를 완화하지 않고
Linux 전용 자원 시험에서 기존 `os.uname().machine`을 사용하도록 수정했다.
90분 컨테이너 시험은 시작되지 않았으며 완료 시간에 포함하지 않는다.

## 보안 스캐너 공급망의 실행 범위 제한 (IMG-05)

2026년 3월 Trivy 공급망 침해의 공식 공지는 악성 0.69.4 및 일부 이미지·Action tag를
명시한다. 현재 고정한 0.76.2가 침해됐다는 의미는 아니다.
[공식 공지](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23),
[조사 결론](https://github.com/aquasecurity/trivy/discussions/10462)을 참고했다.

기존 hash 고정·깨끗한 환경 변수만으로는 호스트에서 실행한 스캐너의 파일/소켓 접근을
제한할 수 없었다. 신뢰하는 수집기가 Docker image archive를 만들고, 스캐너는 그 파일과
전용 cache/output만 마운트한 non-root/read-only 컨테이너에서 실행하도록 변경한다.
Docker 소켓·checkout·호스트 HOME·클라우드 자격은 마운트하지 않는다. DB 다운로드만
bridge network를 사용하며 실제 스캔·변환은 network none이다. 현재 이미지 자체를
실행 환경으로 재사용하므로 별도 mutable scanner image를 추가하지 않는다.

스캐너가 만든 symlink/hardlink/FIFO 또는 과대 파일을 호스트 증거 수집기로 읽지 않는다.
이 격리는 호스트 자격 노출 범위를 줄인다. 악성 스캐너의 거짓 판정을 탐지하거나 컨테이너
탈출까지 방어한다고 주장하지 않는다. 기존 전체 심각도·정확한 패키지 집합·최신 DB·
HIGH/CRITICAL BLOCK 기준은 그대로다. 실제 amd64/arm64 CI 통과 후 인계에 사용한다.

IMG-05 첫 CI `42259850201`은 양쪽 아키텍처의 기존 통합 시험을 통과한 뒤 격리 DB 다운로드에서
중단됐다. 결과를 UNKNOWN으로 유지하고, 원문 stderr 대신 고정 오류 분류만 내보내는 진단을
추가해 원인을 조사한다. 앞선 이미지 PASS와 진행 중인 4511a43 지속 시험은 별도 증거다.

CI `42261162591`의 고정 진단은 `storage-full`이었다. DB 압축 해제가 작은 256MiB tmpfs를
소진한 것으로 보고 TMPDIR을 이번 호출 전용 디스크 cache 아래로 옮겨 재검증한다. 호스트 HOME이나
일반 /tmp를 마운트하지 않고 native Linux 6GiB 여유 조건을 유지한다. scanner CLI가 timeout으로
끝나도 컨테이너 종료를 추정하지 않는다. 무작위 실행 label·정확한 ID/name/image를 대조한
소유 컨테이너만 정리하는 finally 경로도 추가한다. 잘못된 identity에서는 삭제하지 않는다.

- T28 추가 결과: sova-test `a8a51cc`, CI `42260455022` 성공. process/container 소비 각각
  44 PASS, T28/원장/PG **30 PASS / 1.99초**. 별도 HTTP 프로세스가 호출자 사망 후 늦게 효과를
  만드는 경우도 재호출하지 않았다. terminal 확인 전 reconcile은 거부했다. 합성 효과이며
  실제 공급자 fencing/운영 인수를 대신하지 않는다.
- OPS-01 접속 자료 보완: 사용자 다운로드의 기존 팀 ZIP에서 실제 비공개 `team-test.json`을
  발견했다. 주소·사용자 매핑은 출력하거나 Git에 보존하지 않았다. 인증 없는 두 경로의 GET
  전송 점검은 DNS 해석 단계에서 중단됐다. Windows/WSL 기존 Tailscale 도구가 확인되지 않아
  본인 tailnet 로그인/접속이 남는다. 플랫폼 변경·토큰 발급·자원 생성은 수행하지 않았다.
  [기존 도구별 실제 인수 실행안](../platform-live-acceptance.md)에 선행 조건과 근거를 정리했다.

IMG-05의 `f333c56` CI에서는 격리 DB 다운로드와 scan/convert를 마친 뒤 파일 제한에서 중단됐다.
큰 DB를 1GiB로 가정했던 상한을 4GiB로 변경하고 실측 크기를 기록한다. JSON/SBOM 상한과
symlink/hardlink 거부, 6GiB 시작 여유 조건, 취약점 판정 기준은 유지한다.
파일 종류·link 수·크기 진단을 구분하며 재검증 전 결과는 UNKNOWN으로 유지한다.

## 사용자 대상 확인과 추가 플랫폼 갱신

사용자가 플랫폼은 `bravo-personal` SSO → 기존 SSM API 포워딩, namespace `platform-state`라고
확인했다. `default`는 다른 계정이며 팀 접속 ZIP/`.local-tools` 설정은 온프렘 목적지용이다.
앞선 ZIP의 DNS 실패를 플랫폼 결과로 취급하지 않는다. 실제 로그인·실환경 검증은 데모용 맥에서
후속 진행하도록 사용자가 지정했다. 현재는 일괄 배포와 겹치는 공용 변경 없이 인계 준비만 한다.

작업 중 develop이 42811da에서 `0795f65e24f58e43545b16b97757efcc0923fd4a`로 39개 커밋 진행됐다.
새 T24 follow를 재사용하도록 인계를 수정했고, T10의 실행 직전 재평가·호스트 자체 주체·SHIFT
분리와 reader v2의 같은 rollout 조건을 검토했다. 열한 번째 소비 기준과 최신 실제 이미지/T10
시험을 추가한다. 새 T28의 platform-context 상태 조회 subprocess 우회와 initial_args 결속도
별도로 보강한다. 두 이전/최신 driver의 원문 hash를 고정하고 이전 재시작 시험을 함께 유지한다.

IMG-05 `0c17b82`, CI `42263097644`는 native 두 아키텍처 모두 성공했다. 실제 DB는
**1,675,673,600 bytes**로 앞선 1GiB 상한을 넘었다. 전용 디스크 TMPDIR과 4GiB DB 한도로
다운로드/검사/변환/정리와 export/reload를 완료했다. offline archive 검사에서 전체 심각도 0건이다.

최신 T28 `0f032c0`, CI `42264289594`: 최신 0795f65에서 **36 PASS / 2.13초**, 이전 42811da에서
**32 PASS / 4 SKIP / 2.02초**. skip은 이전 driver에 없는 AI start/collect 인자 시험 네 개다.
양쪽 producer 소비 44 PASS는 아직 이전 고정 패키지 기준이며 최신 producer pin 검증은 후속이다.

T10 재평가에는 별도 소비 시험 8개를 추가한다. 합성 저장 GATE report만 과거 시각으로 설정하고
현재 원문 근거는 그대로 둔다. 새 T19 PASS에도 추가 보안 근거가 없으면 차단하고, 새 판정 BLOCK/
readiness binding 변경은 원격 호출 전에 차단한다. 정상 시 과거 report와 새 reevaluation 원본을
별도로 보존하며 단일 POST/이후 GET을 유지하는지 확인한다. 실제 근거의 만료를 갱신하는 시험이 아니다.

공간 guard가 다시 충족돼 작업 전용 WSL checkout만 0795f65로 갱신하고 focused 검증을 수행했다.
최신 플랫폼 소비·재평가 **34 PASS / 13.70초**, 최신 T28/SQLite 원장 **34 PASS / 4.71초**.
Windows 팀 platform checkout은 505d451 그대로이며 수정하지 않았다. PostgreSQL 두 시험을 포함한
T28 36개 결과는 앞선 원격 CI와 구분한다.

배포 원본을 추가 확인했다. 0795f65의 registration/rehearsal-host pin은 실제 발행 source
`445848d2ed9878e31eb6f5aabad0575c61739b47`이며 workflow-host도 registration pin을 사용한다.
개발 HEAD로 runtime SHA를 대신하지 않도록 445848d를 열두 번째 계약 기준으로 별도 검증한다.
이 선언을 실제 rollout 완료로 해석하지 않으며 맥의 읽기 전용 확인에서 현재 digest/revision을 대조한다.

발행 source 445848d의 focused 실제 모듈 소비 시험도 **34 PASS / 13.24초**다.
runtime image source와 develop 계약 기준을 모두 별도로 남긴다.

## 최종 고정 생산자와 소비 검증

생산자 `546f6e0482cc06fa32f00ea8d554522551a84beb`의
[CI 42265872242](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42265872242)는 성공했다.
Python 3.14 전체 **1,084 PASS / 2 SKIP**, 12개 계약 기준을 유지하며 최신 0795f65와 실제 발행
원본 445848d의 소비·재평가 시험은 각각 **34 PASS**다. native amd64·arm64 모두 PG18.4 58개,
TLS/HBA 1개, 서비스 이미지/T10 11개와 격리 스캔·export/reload를 통과했다.
OS 38개/Python 10개 대조 후 전체 심각도 0건이다. 이미지·입력 ZIP hash와 원본별 결속은
[이미지 증거](../evidence/service-image-scan-2026-11-07/README.md)에 보존한다.

소비자 `a177276761f601428d54df57dc4a2000274c6ac1`은 이 생산자를 정확히 고정한다.
[CI 42266814087](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42266814087)에서
process **44 PASS / 67.36초**, container **44 PASS / 48.77초**, 최신 T28 **36 PASS / 2.16초**,
이전 T28 **32 PASS / 4 SKIP / 2.02초**다. 앞선 이전 패키지 소비와 구분되는 최종 결과다.

후속 문서·원본 증거 커밋은 검증한 코드 생산자 pin을 바꾸지 않는다. 이 결과는 개인 환경의
실제 프로세스/컨테이너·PG·TLS 검증이며 실제 플랫폼 배포나 다섯 운영 인수 항목의 PASS가 아니다.
실제 로그인·읽기 전용 대조 및 별도 변경 시험은 사용자가 지정한 데모용 맥으로 인계한다.
