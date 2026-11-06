# 실제 서비스 프로세스의 회전·철회 지속 시험

## 연결 수 예산을 포함한 마지막 30분

`ci-budget-30m.json`, source `68ec7316cdd9855f1977ddb0edcb93c12267e324`의
[CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42240519877)는
15:10:53Z~15:40:54Z, 실제 **1,800초**, pytest **1 PASS / 1,801.61초**다.
60회 회전 동안 정상 120회, issuer/grant 철회 거부 각각 60회, 실제 만료 거부 56회였다.
RSS는 62,648→최대 63,036KiB, descriptor 7/thread 2를 유지했고 본인 서비스 종료를 확인했다.
전체 114개 src Python 파일과 시험 SHA-256을 해당 Git source에 대조했다.

이 source는 감사 이후 현재 권한·연결 전 DB 검증·TEMP/대형 객체 제한·역할별 연결 수 예산을 포함한다.
최종 소비 source `ec4aac6`과 제품 src의 차이는 platform_review의 기본/허용 SHA 목록뿐이며,
새 아홉 번째 플랫폼 계약과 fixture 정리 재시도는 최종 전체 CI에서 별도 검증했다.
이 결과를 최종 source 전체의 3시간 관찰로 표현하지 않는다.

## 90분 원격 CI

`ci-90m.json`은 source `c4730bba8bba94a4cbdb0acbfe53eb2b72bda2d7`의
[CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42229083403)에서
13:53:53Z~15:23:55Z 관찰했다. 실제 관찰 **5,400초**, pytest **1 PASS / 5,401.77초**다.
원본 ZIP·보고서 해시와 모든 114개 src Python 파일/시험 파일 해시를 Git source와 대조했다.
[공개 출처 명세](ci-provenance.json)에 artifact ID와 원본 SHA-256을 보존한다.

| 항목 | 90분 결과 |
|---|---:|
| 주기 / 자격 교체 | 180 / 180 |
| 정상 판정 | 360 |
| 발급자 철회 / grant 철회 거부 | 180 / 180 |
| 실제 만료된 자격 거부 | 176 |
| RSS 시작 → 최대 | 62,848 → 63,352 KiB |
| descriptor / thread | 7 / 2, 변화 없음 |
| 본인 서비스 프로세스 종료 | 확인 |

이 source는 감사 이후 현재 권한 및 연결 전 DB 경로 검사를 포함한다. 이후 추가한 TEMP/대형 객체와
연결 수 제한, 여덟·아홉 번째 플랫폼 기준의 검증으로 소급하지 않는다. 각각 별도 source/CI로 기록한다.
실제 PG18.4/TLS/Ed25519/서비스 프로세스와 합성 issuer·측정 원본을 구분한다. 운영 부하·메모리 누수
전체 부재·실제 kubelet 회전이나 22개 통제 인수를 주장하지 않는다.

## 초기 구현 3시간과 저장 생성 제한 수정본 30분

아래 로컬 재검증 외에 다음 두 CI도 완료됐다. 서로 다른 source/중첩된 시간의 실행이므로
한 프로세스의 연속 관찰 시간으로 합산하지 않는다.

| 항목 | 초기 source 3시간 | 저장 생성 제한 source 30분 |
|---|---:|---:|
| 실제 관찰 초 | 10,800.001 | 1,800.000 |
| 주기 / 자격 교체 | 360 / 360 | 60 / 60 |
| 정상 판정 | 720 | 120 |
| 발급자·grant 철회 거부 | 각각 360 | 각각 60 |
| 실제 만료 거부 | 356 | 56 |
| RSS 시작 → 최대 KiB | 62,108 → 62,620 | 62,804 → 63,204 |
| descriptor / thread | 7 / 2 고정 | 7 / 2 고정 |
| 본인 서비스 종료 | 확인 | 확인 |

- [3시간 CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42217767600),
  `ci-3h.json`, source `163111eee50f26ebe1f5cc3d5a50cbc0870ec85c`,
  12:27:42Z~15:27:44Z, **1 PASS / 10,802.96초**. 113개 src 파일과 시험 해시를 대조했다.
  이 source는 후속 감사 이후 권한 재검사·연결 전 DB 검증·생성 제한·연결 수 상한을 포함하지 않는다.
- [저장 생성 제한 30분 CI](https://github.com/Softbank-Hackathon-Finals/security/actions/runs/42238259304),
  `ci-storage-30m.json`, source `5ddf281b31568e49cdd1a2c993e8d8172cdc7b1e`,
  14:56:13Z~15:26:15Z, **1 PASS / 1,801.61초**. 114개 src 파일과 시험 해시를 대조했다.
  이 source는 TEMP/대형 객체 제한을 포함하지만 이후 연결 수 상한은 포함하지 않는다.

모든 원본 ZIP/report/source/test 대조 값은 `ci-provenance.json`에 있다. 아래의 로컬 실행은
실행 위치·source가 다른 별도 결과다.

## 감사 이후 권한 확인을 포함한 180초 로컬 재검증

`receipt-fix-180s.json`은 2026-11-06T13:28:15Z~13:31:16Z의 로컬 실제 PostgreSQL 17.11/TLS
서비스 프로세스 측정이다. 실행은 **1 PASS, 181.50초**였다. 보고서의 모든 `src/sova_security/*.py`
및 시험 파일 SHA-256을 Git source `d9c878f7be63b72a2d693f24af37148776fb7fe2`와 직접 대조했다.
이는 앞선 3시간 CI가 시작된 이후의 감사/현재 권한 수정까지 포함한다.

| 항목 | 결과 |
|---|---:|
| 관찰 주기 / 단기 credential 회전 | 6 / 6 |
| 허용 판정 | 12 |
| issuer 철회 / grant 철회 거부 | 6 / 6 |
| 실제 만료된 이전 credential 거부 | 2 |
| RSS 시작 → 최대 | 58,984 → 59,312 KiB |
| 파일 descriptor / thread | 8 / 2, 변화 없음 |
| 종료 | 본인 서비스 프로세스 중단 확인 |

TokenReview 공급자와 보안 원본 내용은 합성이며 실제 서명·PG·TLS·별도 프로세스를 사용했다.
판정 TTL은 원래 5초 이내, execution_authorized는 false다. 운영 발급기·kubelet/CNI·부하 한계나
장기간 메모리 안정성 전체를 입증하지 않는다. Windows 공간 소진으로 SIGBUS가 난 이전 로컬 장시간
실행은 이 결과와 합치지 않는다. 3시간 CI의 source와 결과도 위처럼 별도로 기록한다.
