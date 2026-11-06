# HIGH 49건 이후 이미지 재자격

기존 [Debian 원본](../service-image-scan-2026-11-06/README.md)의 HIGH 49건은 보존한다.
공식 digest 고정 Python 3.12.16 Alpine 3.24.4로 변경한 뒤 native amd64·arm64에서
실제 설치 목록과 scanner 전체 목록을 대조했다. 미수정 취약점 예외·VEX·ignore를 추가하지 않았다.

| 검증 source | 아키텍처 | OS / Python 패키지 | 전체 심각도 발견 | 판정 |
|---|---|---:|---:|---|
| [338f755 최초 결과](qualified-338f755/README.md) | amd64 | 38 / 10 | 0 | PASS |
| 4511a433d9a8af8bab7426cb934842a96bca5290 | amd64 | 38 / 10 | 0 | PASS |
| 4511a433d9a8af8bab7426cb934842a96bca5290 | arm64 | 38 / 10 | 0 | PASS |
| 546f6e0482cc06fa32f00ea8d554522551a84beb | amd64 | 38 / 10 | 0 | PASS |
| 546f6e0482cc06fa32f00ea8d554522551a84beb | arm64 | 38 / 10 | 0 | PASS |

Trivy 0.76.2의 해당 DB·관측 시점에 대한 정책 판정이다. 모든 잠재 취약점 부재, registry 발행,
서명, 실행 승인 또는 실제 플랫폼 배포를 뜻하지 않는다. 스캔은 만료되므로 실제 발행 시 다시 확인한다.
4511a43의 platform 계약 기본 기준은 42811da이고 앞선 9개 기준도 유지한다.

최종 producer 546f6e0은 기본 계약을 0795f65로 갱신하고 발행 source 445848d를 포함해
12개 기준을 검증했다. 아래 4511a43의 원본과 최신 producer의 원본을 합치지 않는다.

## 최종 producer 546f6e0

[CI 42265872242](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42265872242)는
모든 job을 성공했다. Python 3.14는 1,084 PASS/2 SKIP이며, native 두 아키텍처 각각 실제 PG18.4
58개·DB TLS/HBA 1개·서비스 이미지/T10 11개를 통과했다. 격리 scanner의 동일 이미지 스캔은 PASS다.

| 항목 | amd64 | arm64 |
|---|---|---|
| job | 128058915751 | 128058915721 |
| 입력 artifact ID | 13525814893 | 13528010133 |
| exact image archive artifact ID | 13525899810 | 13526499441 |
| 원본 대조 | [provenance](qualified-546f6e0-amd64/provenance.json) | [provenance](qualified-546f6e0-arm64/provenance.json) |
| 정책 판정 | [decision](qualified-546f6e0-amd64/decision.json) | [decision](qualified-546f6e0-arm64/decision.json) |
| 실제 설치 목록 | [inventory](qualified-546f6e0-amd64/runtime-inventory.json) | [inventory](qualified-546f6e0-arm64/runtime-inventory.json) |
| archive 결속 | [archive provenance](qualified-546f6e0-amd64/archive-provenance.json) | [archive provenance](qualified-546f6e0-arm64/archive-provenance.json) |

검사·export·reload는 각 config ID에 결속된다. 최종 546f6e0 이미지 자체를 90분 관찰했다고
표현하지 않는다. 지속 시험은 4511a43이며, final producer의 src 차이는 platform_review의
기본/허용 SHA 목록뿐이다. build/lock과 지속 시험 harness는 같고 최신 계약은 위 CI에서 별도 검증했다.

## 4511a43의 native 양쪽 원본과 이미지 보존

[CI 42257525513](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42257525513)의
이미지 검사·export·재로딩과 두 native 컨테이너의 90분 지속 시험을 모두 완료했다.
[지속 시험 원본](../review-container-endurance-2026-11-07/README.md)에 각각 5,400.001초의
실측·회전/거부 횟수·자원·종료 결과를 별도로 보존한다. 전체 workflow도 성공했다.

| 항목 | amd64 | arm64 |
|---|---|---|
| job | 128030178953 | 128030178728 |
| 작은 입력 artifact ID | 13523527029 | 13524360085 |
| 정확한 이미지 archive artifact ID | 13522774371 | 13523063664 |
| 원본 대조 | [provenance](qualified-4511a43-amd64/provenance.json) | [provenance](qualified-4511a43-arm64/provenance.json) |
| 정책 판정 | [decision](qualified-4511a43-amd64/decision.json) | [decision](qualified-4511a43-arm64/decision.json) |
| 실제 설치 목록 | [inventory](qualified-4511a43-amd64/runtime-inventory.json) | [inventory](qualified-4511a43-arm64/runtime-inventory.json) |
| archive 결속 | [archive provenance](qualified-4511a43-amd64/archive-provenance.json) | [archive provenance](qualified-4511a43-arm64/archive-provenance.json) |

각 폴더의 Dockerfile·잠금 requirements·manifest·scanner version·DB metadata·전체 scan·SBOM을
원본 그대로 보존했다. Git blob의 uv.lock/준비 스크립트/Dockerfile, ZIP digest, wheel digest,
scan/inventory/SBOM hash와 source/platform/local config ID를 대조했다.
image.tar.gz와 wheel 바이너리는 Git에 넣지 않았으며 공개 CI artifact 보존 기한은 14일이다.

export는 동일 source/platform/config ID의 최근 PASS만 허용하고, 다시 Docker load한 컨테이너의
실제 inventory가 원래 출력과 일치해야 한다. artifact ZIP hash, 내부 image.tar.gz hash,
local image config ID는 서로 다른 식별자다. 어느 것도 registry distribution digest로 바꾸어 쓰지 않는다.
플랫폼 반입은 기존 T7/T43 발행·서명·승인 경로에서 해당 아키텍처를 선택해 인수해야 한다.

## 추가 스캐너 격리 변경

후속 수집기는 scanner를 host에서 직접 실행하는 대신 비루트 컨테이너에 이미지 archive만
제공한다. Docker 소켓·checkout·호스트 HOME은 주지 않으며 실제 스캔/변환은 network none이다.
공개 DB 다운로드만 bridge network를 사용한다. 현재 DB 1,675,673,600 bytes의 hash·크기와
실행 격리 방식을 decision에 기록한다. symlink/hardlink/FIFO·과대 출력은 수집하지 않는다.
CLI timeout에도 정확한 실행 label/name/image/ID의 컨테이너만 정리한다.

첫 시도 0a3c3cc와 7b47818은 DB 다운로드 공간, f333c56은 DB 파일 상한에서 실패했다.
0c17b82에서 양쪽 native 스캔을 통과했고 최종 546f6e0도 통과했다. 실패를 PASS로 변경하거나
검사 기준을 완화하지 않았다. [개발 기록](../../development/security-acceptance-2026-11-07.md)에
원인·수정·재검증을 남겼다. 격리는 호스트 자격 노출 범위 제한이며 악성 scanner의 거짓 판정까지
검증하는 독립 attestation은 아니다.
