# ADR-0010: 현재 전체 증거 검증의 결합 계약

- 상태: 구현, 서명·변경·DB 경계 시험 및 계측 완료. 소비 컨테이너 재검증 대기.
- 요구: SEC-PATCH-05·06·10, CTRL-02·07, POL-03·09·11.
- 플랫폼 기준: `9e0d6a59d7a00925ddafc50cfa2ccad00c5ba768`.

## 발견

Sova의 [첫 컨테이너 소비 CI](https://github.com/Softbank-Hackathon-Finals/sova-test/actions/runs/42210670359)는
process 모드는 통과했지만 container 모드에서 4 FAIL / 35 PASS였다. 실패 지점은 실제 효과
적용 전 `validate_permit`의 만료 검사였고, 원래 permit의 기한을 29~92ms 넘겼다. 실패를
무시하거나 만료 시간을 늘리지 않는다. 플랫폼/Sova의 기존 재검사와 단일 효과 원장도 유지한다.

서비스 한 요청의 기존 경로는 전체 원본을 다섯 번 수집했다. 최초 수집 1회와 판단 전후 각각
`authenticate_evidence_batch` + `evidence_for`가 모두 같은 전체 수집·인증을 수행했다.
일반 batch callback이 collection의 최신성을 증명한다고 추측해서 생략할 수는 없다.

## 결정

`SecurityProgramService`에 별도 선택형 `authenticate_current_evidence_batch` 계약을 추가한다.
이 callback은 프로그램·단계·기대 evidence tuple에 대해 **현재 전체 원본을 다시 조회하고,
서명·현재 신뢰·등록·철회를 검증하며, 제거된 마지막 원본까지 포함해 정확히 같은 collection인지**
확인해야 한다. 성공 반환은 정확한 `True`만 허용한다. `None`, `1`, 문자열, tuple은 거부한다.
기존 batch callback과 동시에 지정할 수 없으며 기존 사용자는 원래 검사를 그대로 유지한다.

`RegisteredProgramAuthority`는 이미 이 조건을 충족하는 `SignedProgramEvidence.authenticate_batch`
를 연결한다. 판단 전후 각각 현재 등록을 조회한 **뒤** 이 결합 검증을 수행한다. 마지막 host
조회가 원본 상태를 바꿔도 결합 검증이 그 뒤에 실행된다. 같은 요청에서 즉시 중복되던 별도
`evidence_for` 호출만 제거해 전체 수집은 세 번이 된다. 요청 간 원본·권한·PASS 캐시는 없다.

5초 원격 결과 유효기간, HTTP 제한, original permit 만료, 접수 직전 재검사를 바꾸지 않는다.
원본이 바뀌거나 시간이 지나면 정상적으로 보류한다. 이 변경은 같은 권한을 더 오래 유지하는
갱신 절차가 아니며 wire/DB schema 변경도 없다.

## 검증

- 개별·기존 batch·새 current-batch 경로에서 실제 Ed25519와 철회를 비교한다.
- 마지막 host 조회가 키를 철회하거나 마지막 route/원본을 제거하면 거부한다.
- 관련 서비스/서명 단위 시험 **98 PASS**. 실제 PG 권한/독립 TLS 및 계측 **17 PASS**.
- 잠금 Python 3.14의 계측 실행에서 전체 원본 수집 3회, 함수 호출 약 713만, 계측 시간
  1.956초를 관측했다. 프로파일러를 켠 수치이며 컨테이너 SLA나 운영 성능 보장이 아니다.
- 소비 컨테이너의 실제 만료 실패가 해결됐는지는 후속 고정 SHA CI에서 확인한다.
