# T14·T33 로컬 인수 준비 검증

실제 클라우드 인수가 아닌 개인 패키지·소비 환경의 검증이다. 필요한 공개 필드만
선택한 [summary.json](summary.json)에 코드·CI·native 이미지 출처와 검증 범위를 보존했다.

| 구분 | 실제 결과 | 근거 |
|---|---|---|
| 최신 T10/T19/T33 소비 계약 | 37 PASS, 0 SKIP | [CI 42291826766](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42291826766), platform c364e628 |
| 원래 T33 수집기 회귀 | 183 PASS | 같은 CI, 변경하지 않은 platform 테스트 |
| 전체 패키지 Python 3.14 | 1117 PASS, 5 SKIP | 같은 CI, 격리 PostgreSQL·기존 서비스 통합 포함 |
| 전체 패키지 Python 3.11 | 1059 PASS, 63 SKIP | 같은 CI, 플랫폼 시험의 Python 조건 등 기존 skip 보존 |
| Sova wheel·CLI·정본 모듈 경계 | process/container 각각 11 PASS | [소비 CI 42291343841](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42291343841) |
| Sova 실제 TLS 서비스 소비 | process/container 각각 44 PASS | 같은 소비 CI, 별도 PostgreSQL 원장 사용 |
| T28 접수·재시작·재호출 | 최신 36 PASS, 이전 32 PASS·4 SKIP | 같은 소비 CI, 이전판에 없는 네 인자 시험만 제외 |
| native amd64·arm64 이미지 | 양쪽 모든 취약점 등급 0건, OS 38·Python 10개 대조 | [이미지 CI 42291238009](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42291238009) |

## 정확한 source의 구분

Sova가 설치하는 패키지 source는 `27e6e85514a7cbb3e43d216464b72d9bd78f3fcf`다.
그 뒤 시험·문서 보완 source `3d46637f1347b039814d1476eb859216da3b227b`까지
`src`, `pyproject.toml`, `uv.lock`, `scripts`에는 차이가 없다.

이미지 CI는 PR의 시험 병합 커밋 `1248a7bcad781f378a32c61ab2e78d23a11dfbf9`을 빌드했다.
GitHub Git API에서 이 커밋과 패키지 source의 tree가 모두
`23b17844601a1c0bc1b65f07d6554e1f23479643`인 것을 확인했다. archive의 source를
패키지 source로 바꾸어 표기하지 않는다. 실제 archive SHA-256과 image config ID는 JSON에 있다.

스캔 PASS는 배포 승인이 아니다. registry digest·signed attestation이 없고
`release_authorized=false`다. 과거 0.11.0의 90분 시험은 이번 0.11.1의 지속시간 검증으로 합치지 않는다.
실제 수집·로그인·권한·네트워크·감사·복원 인수는 [맥 실행 안내](../../mac-t14-t33-intake.md)에 남아 있다.
