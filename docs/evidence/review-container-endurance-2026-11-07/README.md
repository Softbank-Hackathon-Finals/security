# Native 컨테이너 90분 지속 시험

2026-11-06 UTC / 11-07 KST. [CI 42257525513](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42257525513)의
native amd64·arm64 job이 모두 성공했다. source는 `4511a433d9a8af8bab7426cb934842a96bca5290`이며
검사·export·reload한 동일 config ID의 Alpine/musl 서비스 컨테이너를 각각 관찰했다.

| 실측 | amd64 | arm64 |
|---|---:|---:|
| 원본 | [amd64.json](amd64.json) | [arm64.json](arm64.json) |
| job | 128030178953 | 128030178728 |
| 보고서 artifact | 13531390560 | 13528189941 |
| 실제 관찰 시간 (초) | 5,400.001 | 5,400.001 |
| pytest 전체 시간 (초) | 5,401.91 | 5,401.34 |
| 반복 / 자격 회전 | 180 / 180 | 180 / 180 |
| 정상 요청 | 360 | 360 |
| 자격 철회 거부 | 180 | 180 |
| grant 철회 거부 | 180 | 180 |
| 실제 만료 이후 거부 | 176 | 176 |
| RSS 기준 / 최대 (KiB) | 54,496 / 55,600 | 54,064 / 55,156 |
| 파일 핸들 기준 / 최대 | 7 / 7 | 7 / 7 |
| 스레드 기준 / 최대 | 2 / 2 | 2 / 2 |
| 소유 child 종료 / 컨테이너 제거 | 확인 / 확인 | 확인 / 확인 |

Docker CLI의 자원 대신 컨테이너 PID 1의 실제 `sova_security.interfaces.review_server`를 확인해
RSS/FD/thread를 측정했다. 각 CI의 실제 PostgreSQL·TLS·컨테이너를 사용하지만 신원 제공자는
로컬 issuer 모형이고 측정 근거는 서명한 합성 데이터다. 실제 kubelet 발급·CNI·운영 부하·장애 복구
또는 실제 플랫폼 다섯 인수 항목의 PASS로 확대하지 않는다. 실행 권한은 항상 false다.

[provenance.json](provenance.json)은 다운로드 ZIP·보고서 hash와 source/test/harness 대조 결과다.
원본의 모든 source 파일 hash를 Git archive와 비교했고 각 image config ID를
[4511a43 이미지 보존 원본](../service-image-scan-2026-11-07/README.md)과 대조했다.
실제 경과 시간, 회전/허용/거부 횟수, 자원 상한 및 소유 프로세스/컨테이너 종료를 검증한 뒤 보존했다.
관측 시간과 pytest/CI 전체 실행 시간을 구분한다.

## 최종 소비 버전과의 관계

최종 producer `546f6e0482cc06fa32f00ea8d554522551a84beb`의 src 차이는
`adapters/platform_review.py`의 기본/허용 플랫폼 SHA 목록이다. Dockerfile·uv.lock·pyproject·
이미지 준비 스크립트·지속 시험과 세 harness 파일은 같은 바이트임을 Git에서 확인했다.
새 12개 계약과 최종 이미지 기능·스캔·export/reload는
[별도 CI 42265872242](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42265872242)에서 성공했다.
따라서 546f6e0 이미지 자체를 90분 실행했다고 쓰지 않는다. 같은 버전 번호도 source/image ID를 대신하지 않는다.

앞선 `02011b5`의 실패는 지속 시험 시작 전 package boundary 검사였고 이번 경과 시간에 합산하지 않았다.
호스트 Python 프로세스의 이전 지속 시험과 이번 컨테이너 결과도 따로 보존한다.
