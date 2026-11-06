# ADR-0013: 자격 교체와 철회의 장시간 실제 프로세스 시험

- 상태: 3시간·90분·저장 생성 제한 30분·연결 수 예산 30분 CI 완료. 각 source의 원본·해시를 별도 보존.
- 요구: CTRL-01·02·04·07, SEC-PATCH-09·10. 플랫폼 기준 `a610bbf`.

짧은 기능 시험과 별도로 같은 보안 서비스 프로세스를 유지하며 실제 시간 경과에 따른
자격 교체·만료·철회와 자원 사용을 관측한다. 기본 pytest에서는 명시적으로 skip하며,
소유한 PG 시험 클러스터와 절대 경로의 새 보고서 파일을 지정한 경우만 실행한다.

`tests/integration/test_review_endurance.py`는 30초마다 client/reviewer 자격을 교체하고
mounted reviewer 파일을 fsync/rename으로 원자적으로 갱신한다. 정상 판정, issuer 철회 거부,
grant 제거 거부, 복원 후 정상 판정을 확인한다. 최초의 실제 2분 만료 자격은 그 시각 이후
계속 거부되어야 한다. 결과 TTL은 여전히 5초 이하이며 실행 권한은 항상 false다.

PG/RLS·원본 Ed25519 연산·TLS·독립 프로세스는 실제다. issuer는 로컬 모형이고 측정 원본은
합성이다. 장시간 쓸 원본/등록 기간은 시작 전에 명시적으로 고정하며 재조회로 연장하지 않는다.
이 시험을 실제 kubelet 회전, 운영 scanner 최신성, CNI, 배포 효과 또는 전체 22개 통제 인수로
확대하지 않는다. 장시간 끝나면 소유한 프로세스와 시험 DB를 종료한다.

warm-up 뒤 RSS 증가 64MiB, descriptor 증가 12개, thread 증가 16개를 상한으로 확인하고
관측값을 기록한다. 이는 운영 부하 SLA나 모든 memory leak 부재 증명이 아니다. 보고서는
token/원문/DSN 없이 소스 파일·시험 해시, 상태·횟수·시각·프로세스 자원 값만 저장한다.

예비 시험: **1 PASS, 181.55초**. 정상 12회, issuer/grant 철회 각 6회, 실제 만료 거부 2회.
descriptor 8개/thread 2개 유지, RSS 59,456→59,692KiB. 운영 트래픽을 사용하지 않았다.

```sh
SOVA_REVIEW_ENDURANCE_SECONDS=13200 \
SOVA_REVIEW_ENDURANCE_REPORT=/absolute/new-report.json \
SOVA_SECURITY_TEST_POSTGRES_DSN='<owned disposable test DB>' \
python -m pytest tests/integration/test_review_endurance.py -q
```

기존 파일에 보고서를 덮어쓰지 않는다. 예시 DSN을 실행 가능한 자격으로 대체해서 커밋하지 않는다.

실측 시간·자원·자격 교체/철회 횟수와 source별 보증 범위는
[지속 시험 원본](../evidence/review-endurance-2026-11-06/README.md)에 있다.
초기 3시간 결과로 이후 수정본을 검증했다고 주장하지 않으며 겹쳐 실행한 시간을 합산하지 않는다.
