# 사고 조사와 호환 가능한 보강

확인일 2026-11-06. 원문 두 제안서가 주 요구사항이며, 아래 조사는 추가 설계 근거다.
사고 발생일과 조사/제재/보고서 발행일을 구분한다. 기사나 공격자 주장을 측정 근거로 사용하지
않으며 피해 데이터·운영 비밀을 수집하지 않았다. 법규 준수 판정이 아니라 설계·시험 관점이다.

## 확인한 사례

| 사례 | 확인한 사실과 출처 | 이 프로젝트의 적용 판단 |
|---|---|---|
| Healthplex, 2021 사고·2025 제재 | 이전 이메일 환경의 MFA가 O365 외부 웹 접근 경로에서 완전히 작동하는지 확인하지 못했다. 감독기관은 이 경로의 MFA 누락과 과도한 메일 보관을 지적했다. [NYDFS 원문, 12~17항](https://www.dfs.ny.gov/industry-guidance/enforcement-discipline/ea20250814-healthplex) | CTRL-05/SEC-PATCH-08: 기존 환경 PASS를 목적지에 복사하지 않는다. 웹·API·workload처럼 실제 접근 경로별 증거를 등록하고 목적지에서 다시 시험한다. 모든 환경의 MFA를 우리 서비스 토큰으로 대체하지 않는다. |
| PayPal, 2022 변경·2025 합의·2026 보고서 | 데이터 수집 흐름 변경 후 민감정보가 마스킹되지 않은 채 노출됐고, 규정된 변경 절차가 지켜지지 않았다고 NYDFS가 정리했다. credential stuffing으로 해당 정보에 접근한 것으로 설명한다. [NYDFS 2025 연차보고서, 인쇄면 4](https://www.dfs.ny.gov/system/files/documents/2026/04/Consumer-Protection-and-Financial-Fraud-Enforcement-Annual-Report-for-2025.pdf) | SEC-PATCH-05·06/CTRL-05: 승인된 정확한 계획을 실행 직전에 다시 확인한다. 적용 후 기능 정상뿐 아니라 실제 민감정보 노출·인가 거부 결과도 필요하다. 사전 검사 결과로 사후 완료 처리하지 않는다. |
| Bayview 계열, 2021 침해·2025 합의 | 같은 감독기관 보고서는 패치 관리, 취약점 개선 감독, 자산 추적의 부족을 기여 요인으로 들었다. [NYDFS 보고서, 인쇄면 3~4](https://www.dfs.ny.gov/system/files/documents/2026/04/Consumer-Protection-and-Financial-Fraud-Enforcement-Annual-Report-for-2025.pdf) | SEC-PATCH-01·02·09: 스캔·수집 실패를 취약점 없음으로 표시하지 않는다. 마지막 실제 성공 시각을 보존하고 오래된 관측을 재수집해 유효기간을 늘리지 않는다. |
| RORZE 대만 자회사, 2025 발표 | 회사는 VPN 접근 이후 가상화 기반 서버에서 랜섬웨어가 실행됐다고 설명했다. 정보 유출 여부는 확인할 수 없었다고 밝혔다. 파산 사례로 발표한 자료는 아니다. [회사 공식 후속 공지, 2025-05-20](https://www.rorze.com/en/news/2025/05/20/2562/) | SG-1/CTRL-01·06: 한 서비스 자격 침해가 다른 tenant의 읽기/쓰기 또는 백업 삭제 권한으로 번지지 않도록 계정과 네트워크를 분리한다. UNKNOWN을 유출 없음으로 바꾸지 않는다. |
| KNP Logistics, 2023 사고·사업 종료에 대한 회고 | 전 임원의 발표를 정리한 행사 주최기관은 백업도 피해를 입었고 재무 보고 시스템 복구 실패가 사업 지속에 치명적이었다고 전한다. 이는 영국 사례다. [EMCSC 발표 정리](https://www.emcsc.co.uk/article/inside-cyber-security-anatomy-of-a-ransomware-attack) | SG-3/CTRL-06: 복구 자산 보유와 실제 업무 복원 성공을 분리한다. DB 연결만으로 복구를 완료 처리하지 않고 T12/T13/T20/T35의 데이터·업무 검증에 연결한다. |

대만 ACS의 2026-07-27 공식 안내는 백업·업데이트·계정 보호와 사고 후 격리·증거 보존·
깨끗한 복원을 강조한다. 이 자료도 특정 대만 회사의 파산을 입증하지 않는다.
[ACS 공식 자료](https://web.moda.gov.tw/ACS/press/news/press/20242).

## 아직 확정하지 않은 사용자 언급

`니케`가 Nike인지 Nikkei인지 이 대화만으로 확정하지 않는다. Nikkei로 보이는 2026년 10월
사건의 [회사 공지 주소](https://www.nikkei.co.jp/nikkeiinfo/news/information/1561.html)는 찾았지만
웹 도구와 직접 읽기에서 본문을 얻지 못했다. 재인용된 건수·원인·피해 범위를 검증된 사실로
채택하지 않았다. Nike 관련 보도도 동일 사건으로 합치지 않았다.

추가 확인한 [NIKE 2026 10-K, Item 1C](https://investors.nike.com/sec-filings/all-sec-filings/content/0000320187-26-000088/nke-20260531.htm)는
과거 사고 경험과 해당 공시 시점까지의 사업·영업실적 중대 영향 부재를 함께 서술한다.
이 공시는 2026년 1월 특정 유출 주장·규모·원인을 확인하는 자료로 사용하지 않는다.
독립 시험, 취약점 관리, 외부 연동 위험 평가를 운영하는 것과 특정 통제의 실제 성공을 구분한다.

`보안을 우선시하지 않은 대만 회사의 파산`은 회사명과 1차 근거를 특정하지 못했다.
다른 나라의 KNP/23andMe/Einhaus 사례로 바꾸거나 보안 소홀을 단독 파산 원인으로 단정하지
않는다. 정확한 사례명이 확보되기 전까지 그 주장만 보류하며 구현 작업은 계속한다.

## 구현·시험에 반영한 항목

1. **자격 침해의 읽기 범위 제한**: 테넌트 전용 SELECT 역할과 restrictive RLS를 추가했다.
   직접 SQL로 tenant GUC를 바꿔도 타 tenant 자료는 보이지 않는다. 정책·권한 drift는 판정을 막는다.
   기존 shared credential RLS의 한계를 명시한 ADR-0002와 실제 PostgreSQL 시험이 있다.
2. **원본 관측 시각 보존**: T33 변환기의 유효기간을 원본 event/last_success에도 결속했다.
   남은 유효기간 1초인 관측을 다시 받아도 1초만 유효하다. 기한을 넘긴 heartbeat는
   coverage-unavailable이며 오래된 finding은 거부한다. wire schema와 플랫폼 코드는 바꾸지 않는다.
3. **실행 직전·직후 경계 유지**: 현재 승인/등록/철회·단일 접수를 실제 T10 모듈과 대조했고,
   Sova 효과 적용 후 서비스 장애에서는 APPLIED와 hold를 유지하며 다시 적용하지 않는다.
4. **서비스 장애 전파 제한**: 입력/응답·worker·시간·DB 읽기·로컬 감사 크기를 제한한다.
   감사 상한에 도달하면 기록을 덮지 않고 새 판정을 보류한다. 앱은 이 서비스의 가용성에
   직접 의존하지 않도록 배포 경계를 둔다.

## 실제 환경에서 이어갈 검증

외부 웹 접근에서 MFA/세션·CSRF·CSP 검증, T7 audience/철회 실측, 서비스 역할로 Secret 읽기·
Pod exec·배포·DB 쓰기 거부, 다른 namespace/tenant 접근 거부, T24 원문 수집·보존 확인,
변경 이후 실제 복원·업무 정합성은 등록된 팀 환경과 담당 공급자가 필요하다. 개인 환경의
합성 PASS로 채우지 않는다. 기존 22개 검사와 해당 경로의 `ProgramEvidenceRoute`에
원본 증거를 연결하며 새 실행 엔진·모델 승인·자동 보류 해제 기능을 만들지 않는다.

## 추가 조사: 연동 토큰의 수평 확산

2025-08 Salesloft Drift 사고의 [Google 조사팀 원문](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift)은
탈취한 OAuth 토큰으로 연결된 Salesforce 자료를 읽고, 그 자료에서 다른 자격을 찾은 행동을
설명한다. 08-28 갱신은 다른 연동도 조사·철회 대상으로 확장했다. 핵심 서비스 자체가 침해된
것과 고객이 승인한 연동 자격이 악용된 것을 구분한다.

이 프로젝트에서는 서비스 자격의 사용 범위를 최소화한다. [ADR-0008](adr/0008-service-token-use-boundaries.md)에
단일 audience·원래 수명 600초 제한을 구현하고, 실제 Kubernetes가 인증한 더 넓은 토큰도
서비스가 거부하는 시험을 추가했다. 기존 토큰 생성기와 실행 권한을 합치지 않는다.
2026-09 [NIST IR 8587](https://csrc.nist.gov/pubs/ir/8587/final)의 workload/audience 지침도
참고했지만 이 변경을 NIST 전체 준수나 탈취 토큰 재사용의 완전한 방지로 표현하지 않는다.

## 추가 대조: 복구와 거버넌스의 실제 이행

Asahi의 [2026-02-18 공식 조사·재발 방지 발표](https://www.asahigroup-holdings.com/en/newsroom/detail/20260218-0201.html)는
2025-09-29 장애 이전의 네트워크 침입, 관리자 권한 획득과 내부 탐색, 여러 서버 암호화를 설명한다.
네트워크 제한·권한 관리·지속 점검·복구 훈련·감독 체계 강화를 제시한다. 발표한 계획과 실제 완료는 구분한다.

이어 [2026-07-27 내부통제 약점 공시](https://www.asahigroup-holdings.com/en/newsroom/detail/20260727-0204.html)는
회계 자료 접근과 대체 업무 절차에 시간이 걸려 결산 자료의 검색·검증을 적시에 완료하지 못했다고 설명한다.
규칙 존재만으로 운영 이행을 보증할 수 없으며, 시스템 재시작과 업무·데이터 검증은 다른 기준이라는 점을
이 프로젝트의 CTRL-06·SEC-PATCH-06·10과 대조했다. 파산 사례나 우리 통제의 성공 근거로 인용하지 않는다.

이번 대조에 앞서 이미 구현한 DB별 HBA/최소 권한, 감사 부분 쓰기 거부, 독립 호스트 보류와 trust-history
복원 회귀가 관련 방어 범위를 제공한다. 이 사고를 재현한 시험으로 표현하지 않는다. 특히 서비스가 과거
신뢰 이력의 복원을 스스로 감지한다고 주장하지 않으며, 호스트 원장까지 함께 되돌아가는 상황은 미검증이다.
후속 플랫폼 인수는 복원 대상과 독립된 차단 → 최신 키/철회와 실제 효과 조정 → 현재 데이터·업무 검증 →
별도 해제 승인 순서로 준비한다. T12/T13/T20/T24/T35의 기존 경로에 원본 증거를 연결하고 중복 복구기를 만들지 않는다.

## 2026-11-07 추가 대조: 승인 화면과 실제 실행 입력

2025-02-21 Bybit 사고에 대해 FBI는 약 15억 달러의 가상자산 탈취를 공지했다.
[FBI/IC3 원문, 2025-02-26](https://www.ic3.gov/PSA/2025/PSA250226).
사고 조사에 참여한 Sygnia는 개발자 단말·AWS 접근과 웹 자원 변조를 거쳐 승인 과정의 거래 내용이
조작된 경로를 정리했다. 일부 세부 내용은 다른 조사팀의 예비 결과를 인용하며 미공개 부분도 구분한다.
[Sygnia 조사 정리, 2025-03-16](https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/).
이 사고는 블록체인 거래 사례이며 우리 플랫폼 사고나 동일 공격의 재현 결과가 아니다.

이 자료에서 도출한 설계 판단은 **사용자가 본 설명·화면과 실행되는 실제 입력의 결속을 별도로
검증해야 한다**는 것이다. 사람의 승인과 서명이 존재한다는 사실만으로 올바른 입력을 보장하지 않는다.
이번 T28 연결은 현재 계획/application·diff/image·정확한 argv·플랫폼 source를 기존 command fingerprint에
결속하고 변경·철회·위조 JSONL을 차단한다. 새 T10 재평가 시험은 과거 GATE 기록과 실행 직전 판정을
분리한다. 이 두 변경은 사고를 읽기 전에 구현한 기존 보강이며 금융 사고 대응 기능을 새로 복제하지 않는다.

| 남길 경계 | 구현 또는 현재 시험 | 실제 플랫폼 인수에 남는 것 |
|---|---|---|
| 승인과 현재 실행 입력 일치 | Sova `test_platform_t28_restart.py`의 changed registration·initial args 거부, 현재 T10 authority 소비 | 승인 UI가 표시한 대상·diff·distribution digest와 서버의 canonical 승인 payload가 같은지 독립 대조 |
| 과거 PASS 재사용 방지 | `tests/contracts/test_platform_reevaluation_bridge.py`, initial/post_apply별 새 BLOCK·binding 변경·추가 근거 누락 차단 | 실제 생산자 원문·시각·현재 등록·계획 잠금 연결 |
| 파일 이름과 실제 내용 구분 | T28의 argv는 정확히 결속하지만 파일 내용 자체를 인증하지 않음을 명시 | 기존 공급자 adapter.validate에서 등록된 입력 digest와 실제 읽은 내용을 대조. 운영 입력이 미결속이면 보류 |
| 승인자와 실행 주체 분리 | 최신 T10의 host subject/apply_change 흐름을 그대로 소비 | 개발자·UI 자격이 실제 변경 경로를 우회하지 못하는 IAM/RBAC 거부와 허용 대조 |

추가 운영 시험은 현재 읽기 전용 Mac 확인 이후 별도 시험 창에서 수행한다. 이 표를 기존 22개 검사나
전체 금융권 보안 인수 PASS로 환산하지 않는다. 승인 UI 변경이나 새 발급·서명 체계는 이번에 추가하지 않았다.

## 2026-11-07 추가 대조: 보안 도구도 공급망 입력

Trivy의 공식 공지는 2026-03-19의 악성 0.69.4 발행·Action tag 변조와 03-22의 일부 Docker 이미지
변조를 설명한다. 이미 고정한 0.76.2가 침해됐다고 주장하는 근거는 아니다.
[공식 GHSA](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23).

이 사건에서 도출한 최소 권한 판단을 이번 IMG-05에 반영했다. hash 고정뿐 아니라 scanner를
호스트 Docker socket/checkout/HOME 없이 제한된 컨테이너에서 실행하고 archive만 제공한다.
실제 검사/변환은 network none, DB 다운로드만 bridge다. scanner가 생성한 link/FIFO·과대 출력은
호스트에서 수집하지 않는다. 구현은 `scripts/scan_service_image.py`, 시험은
`tests/contracts/test_scanner_isolation.py`, 실제 두 아키텍처의 결과는
[최종 이미지 근거](evidence/service-image-scan-2026-11-07/README.md)에 있다.

이는 유출 가능한 CI 자격과 파일 접근 범위를 줄이는 조치다. 독립 scanner의 교차 검증이나 서명된
발행 증명은 아니므로 악성 도구의 거짓 PASS까지 방어한다고 표현하지 않는다. 기존 플랫폼 발행·서명
경로를 인수하고, 실제 발행 시 새 scan과 검토한 도구 source/artifact를 확인하는 조건을 유지한다.
