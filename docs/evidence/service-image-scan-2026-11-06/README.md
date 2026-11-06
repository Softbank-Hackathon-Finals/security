# 서비스 이미지 실제 취약점 검사 — 배포 BLOCK

- 대상 source: `f344aece4eecbed94f0e2ba7b415e67c8d8bb412`.
- [CI 실행](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42217523350),
  [artifact](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42217523350/artifacts/13502033047).
- artifact ZIP SHA-256: `9aa812be78b1693cfe1f5e6356dce7156d0c82ce2d83abcaf2756f6e939e6c35`.
- 관측: 2026-11-06T12:29:46Z, Trivy 0.76.2, DB 갱신 2026-11-06T09:50:00Z.
- 원본 `scan.json`, `decision.json`, DB metadata, 실제 runtime inventory를 보존한다.
  서명된 운영 attestation이나 T24 원장이 아니다. image ID는 registry digest가 아니다.

| 항목 | 실측 |
|---|---:|
| Debian OS packages | 87 |
| 서비스 venv Python packages | 10 |
| CRITICAL / HIGH / MEDIUM / LOW | 0 / 49 / 80 / 63 |
| HIGH 고유 CVE | 13 |
| 수정 버전이 제시된 finding | 6 (전부 기본 이미지의 pip 25.0.1) |

49는 패키지별 finding 수이며 서로 다른 CVE 49개를 뜻하지 않는다. HIGH 항목은 전부 이
보고서의 `FixedVersion`이 비어 있다. 미수정·fix_deferred 항목을 무시하지 않으므로 **BLOCK**이다.
수집 CI의 성공은 이 정책 판정의 PASS를 뜻하지 않는다. 운영 발행/배포는 수행하지 않았다.

## 후속 조치와 근거

서비스 venv 밖의 기본 이미지에 pip 25.0.1이 남아 있었다. runtime에서는 패키지를 설치하지
않으므로 기본 pip와 ensurepip를 제거하고, build 단계의 installer는 기존 lock의 pip 26.2.2
wheel hash로 고정한다. 실제 컨테이너에서 venv 및 global site-packages/entrypoint를 확인하고
이미지를 재스캔한다. 수정 완료는 새 원본 결과를 얻은 후 판단한다.

OS HIGH는 알려진 수정 버전이 없는 항목을 숨기거나 불안정 배포판 패키지로 임의 교체하지 않는다.
2026-11-06 조회한 Debian 원문은 다음을 보여 준다.

- [util-linux CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642):
  trixie 패키지는 vulnerable, sid의 수정 버전과 구별된다.
- [SQLite CVE-2026-119373](https://security-tracker.debian.org/tracker/CVE-2026-119373):
  trixie는 vulnerable이며, FTS5의 특정 입력/질의 경로가 문제다. 해당 경로를 안 쓴다는 추측을 VEX로 만들지 않는다.
- [zlib CVE-2026-76844](https://security-tracker.debian.org/tracker/CVE-2026-76844):
  trixie는 vulnerable이며 sid 수정 상태와 다르다. 쓰기 실패 뒤 gz API 경로의 문제다.

이는 13개 CVE 전체의 수동 검증이나 실제 exploit 시험이 아니다. non-root·capability 제거·
read-only·no-new-privileges를 보완 통제로 유지하되 scanner severity를 임의 낮추지 않는다.
수정된 지원 기반 이미지가 나오면 정확한 digest를 갱신하고 OS/Python 스캔과 T10 소비를
반복한다. 별도의 예외가 필요하면 플랫폼의 기존 승인/기한/보완 통제 경로에서 판단해야 한다.

데이터 흐름은 `고정 source → 이미지 build → 실제 inventory → 원본 scan/DB → 진단 BLOCK`
이다. 향후 registry 발행과 원본 verifier 등록 전에는 기존 `artifact-provenance` PASS로 투영하지 않는다.

## installer 제거 후 재검사

`after-installer-removal/`은 `f1edf095b279a2829b0e3d7a75de375e1f073105`의 별도 원본이다.
[CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42219645504)와
[artifact](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42219645504/artifacts/13503331203)의
ZIP SHA-256은 `c91c65e58932ff9ac040c742d0dd7e9900414b6398f50030a7f8ec2e7c0677c7`이다.
같은 DB 갱신을 사용했고 새 image/source/report digest로 수집했다.

- 기본 pip/ensurepip와 global Python package/entrypoint 부재를 실제 컨테이너에서 확인했다.
- MEDIUM 80→75, LOW 63→62로 pip 관련 6 finding이 없어졌다. HIGH 49 / CRITICAL 0은 그대로다.
- 실제 image/T10 연결 **11 PASS, 37.04초**, PG18.4 경계 **42 PASS, 12.25초**.
- 정책은 여전히 **BLOCK**이다. OS 87개 / 서비스 Python 10개가 있는 같은 기능 경로를 유지한다.
- 이 원본은 v1 수집 정책이다. 이후 도입하는 실제 dpkg inventory와의 완전 일치 검사를 이 결과에
  소급 적용했다고 주장하지 않는다.
