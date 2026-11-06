# Mac 인수 준비 증거

이 폴더는 **로컬 준비 결과**다. 공용 플랫폼 조회·배포·정책 시험·복구를 수행하지 않았다.
실제 운영 결과는 `LIVE_NOT_OBSERVED`로 유지한다.

| 파일 | 의미 |
|---|---|
| `image-verification.json` | 지정 arm64 archive의 해시·config ID·OCI source 대조. load/run/발행 없음 |
| `platform-source-comparison.json` | 고정 develop 차이와 GitOps 선언. actual imageID 아님 |
| `platform-contract.log` | 기존 bridge 시험 34개, 고정 platform `445848d`, 합성 신원·SQLite |
| `t28-local.log` | 기존 T28/원장 시험 34개, 고정 platform `0795f65`, 합성 효과·SQLite·loopback HTTP |
| `t28-source-guard.jsonl` | driver import 허용/거부. 실제 operator 실행 없음 |
| `manifest.json` | 위 원본의 크기와 SHA-256. 서명된 실행 승인이나 운영 영수증은 아님 |

Mac Python 3.12.16, security `871d38aa2fa388d9a2831cbfb07ed24d6d14e413`의 코드·lock은
생산자 `546f6e0482cc06fa32f00ea8d554522551a84beb`와 동일하다.
sova-test 기준은 `ed1a9ad4e05325cfc7013692f63c973165980e36`다.
정확한 시험 범위·명령에 해당하는 파일 목록은 [개발 기록](../../development/mac-acceptance-preparation-2026-11-07.md)에 있다.

GitHub artifact ID `13526499441`의 내부 archive와 커밋된 provenance를 대조했다.
archive 자체는 Git에 넣지 않았다. 공개 증거는 CA·개인키·토큰·계정·endpoint·개인 경로를 포함하지 않는다.
원래의 이미지 스캔과 90분 시험은 각각 원래 폴더에 보존하며 새 실행으로 집계하지 않는다.
