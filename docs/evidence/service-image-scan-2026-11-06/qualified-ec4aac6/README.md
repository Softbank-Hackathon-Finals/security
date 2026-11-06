# 최종 소비 source의 이미지 검사 원본

- source: `ec4aac6c3d839111f76ef7466f7b6fc7fcea1e49`, linux/amd64.
- [CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42242142761),
  [artifact](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42242142761/artifacts/13517222056).
- ZIP SHA-256: `4d0bfb383cb58dabde49ef21ab40bd6596ecb55e113f0147d03e4ac6e423d744`.
- 관측 2026-11-06T15:25:23Z, Trivy 0.76.2, DB 갱신 12:55:02Z.
- local image config ID: `sha256:884c76e68a3138d88997f90a227d594703e7994d36c675d93a709b6bb2031f96`.

실제 OS 87개/Python 10개를 대조했다. **CRITICAL 0 / HIGH 49 / MEDIUM 75 / LOW 62 / UNKNOWN 0,
BLOCK, release_authorized=false**다. HIGH는 고유 CVE 13개에 대한 패키지별 탐지 49개다.
현재 base/OS의 미수정 위험을 예외·VEX 추정으로 숨기지 않았다. 이 이미지의 운영 발행/배포는 하지 않았다.

[manifest.json](manifest.json)의 source·wheel/lock/preparation/Dockerfile/requirements 해시,
[decision.json](decision.json)의 scan/SBOM/runtime inventory 해시와 local image ID를 직접 대조했다.
lock과 준비 스크립트는 해당 Git commit 바이트와 일치하고 artifact ZIP digest도 GitHub metadata와 일치했다.

| 보존 파일 | 용도 |
|---|---|
| [provenance.json](provenance.json) | CI/job/artifact와 각 파일 SHA-256 |
| [scan.json](scan.json) | scanner 원본 |
| [sbom.cdx.json](sbom.cdx.json) | 전체 스캔 입력 재고 |
| [runtime-inventory.json](runtime-inventory.json) | 실제 컨테이너의 OS/Python 재고 |
| [database-metadata.json](database-metadata.json) | scanner DB 갱신 시각 |
| [manifest.json](manifest.json) | 고정 source와 이미지 준비 입력 결속 |

wheel 바이너리는 Git에 중복 저장하지 않았으며 artifact의 바이트와 manifest SHA-256을 대조했다.
scanner DB 바이너리도 이 폴더에 보관하지 않는다. 같은 역사적 DB로 검사를 재실행했다는 뜻은 아니다.
원본의 source/image/report 결속은 수집 근거이며 서명된 attestation·레지스트리 digest·운영 T24 원장은 아니다.
ARM64나 실제 클러스터 운영 인수는 별도로 요구한다.
