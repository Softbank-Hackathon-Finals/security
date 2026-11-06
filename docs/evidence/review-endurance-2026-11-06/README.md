# 실제 서비스 프로세스의 회전·철회 지속 시험

## 감사 이후 권한 확인을 포함한 180초 재검증

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
실행은 이 결과와 합치지 않는다. 별도 3시간 CI의 source와 결과는 완료 후 따로 기록한다.
