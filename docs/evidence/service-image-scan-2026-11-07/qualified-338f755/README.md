# Alpine 이미지 전체 스캔 PASS (개인 CI)

2026-11-06 16:32 UTC / 11-07 01:32 KST. Source
`338f7555ced0ede04858c7e1257a2ce412afd192`.
[CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42252529744),
[image job](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42252529744/job/128012883390).

| 항목 | 기존 Debian ec4aac6 | Alpine 338f755 |
|---|---:|---:|
| OS 실제 설치·스캔 대조 | 87 | 38 |
| Python 실제 설치·스캔 대조 | 10 | 10 |
| CRITICAL | 0 | 0 |
| HIGH | 49 | 0 |
| MEDIUM | 75 | 0 |
| LOW | 62 | 0 |
| UNKNOWN | 0 | 0 |
| scanner policy | BLOCK | PASS |

공식 digest 고정 Python 3.12.16 Alpine 3.24.4로 변경했다. 취약한 패키지를 scanner에서
숨기거나 ignore하지 않았고, APK DB를 보존해 이름·전체 버전·아키텍처를 전부 대조했다.
Trivy 0.76.2와 2026-11-06 12:55:02 UTC DB를 사용했다. 이전 Debian 결과도 보존한다.
발견된 취약점 0건은 이 scanner·DB·시점의 결과이며 모든 잠재 취약점이 없다는 뜻은 아니다.

glibc → musl 변경을 실제 컨테이너로 검증했다: PostgreSQL 18.4 경계 **58 PASS / 13.33초**,
DB TLS/HBA **1 PASS / 0.42초**, container TLS·issuer 철회·T10 연결 **11 PASS / 39.59초**.
기준 플랫폼은 `7edab5312f965bd683a7738e74d49b883190e8da`; 최신 42811da 소비 시험은 별도 후속이다.

local config ID: `sha256:43b643ce5e1e33de8c8aaddbead722cb75fb875b86562e528fd35951cb1c9205`.
**registry distribution digest가 아니다.** 발행·서명·운영 배포는 수행하지 않았다.
검증 아키텍처는 linux/amd64이며 ARM64 운영 인수로 확대하지 않는다.

artifact `13521208308` ZIP SHA-256:
`bd74ca53c2ead6a999ac5ba4648934b0ede29c99d49f33979a632d8ae400bd6c`.
다운로드 후 ZIP·wheel·lock·준비 스크립트·Dockerfile·scan·inventory·SBOM hash를 서로 대조했다.
[provenance.json](provenance.json)은 보존한 11개 원본 파일의 hash를 담는다.
wheel 바이너리와 임시 다운로드 URL은 저장소에 넣지 않았다.
