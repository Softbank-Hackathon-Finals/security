# ADR-0011: TLS 요청 전체의 공통 시간·HTTP 부가 정보 한도

- 상태: 구현 및 실제 loopback TLS·Python 3.11/3.14 전체 CI·3.12 이미지 검증. 운영 DNS/CNI 인수 전.
- 요구: SEC-PATCH-05·06, CTRL-07, POL-03·09·11. 플랫폼 기준 `9e0d6a5`.

## 발견과 선택

기존 `HTTPSConnection(timeout=...)`의 timeout은 전체 요청 시간이 아니다.
헤더를 조금씩 보내는 상대는 여러 번의 socket read를 일으켜 시간을 연장할 수 있다.
`Connection: close` 응답은 `getresponse()`가 connection의 socket을 비운 뒤에도 response의
file이 같은 소켓을 유지한다. 따라서 기존 body loop의 `connection.sock` 검사도 남은 시간을
항상 적용하지 못했다. 본문 한도만으로 HTTP 헤더/청크 부가 정보 크기가 제한되지 않았다.

별도 watchdog thread나 자동 재시도 대신 stdlib HTTP 파서에 한 요청의 monotonic deadline을
연결한다. TCP 주소 시도·TLS handshake·각 send·각 실제 read에 남은 시간을 적용한다.
응답이 소유하는 socket file을 감싸므로 connection 객체가 socket을 놓아도 적용된다.
상태 행·중간 100 응답·헤더·청크 framing·trailer의 누적 `readline` 정보는 20,000 byte 이하로
제한한다. 본문 크기 한도는 별도로 유지한다. 청크 trailer가 끝나기 전 EOF도 거부한다.

TLS 신뢰 CA/hostname 검증, 고정 origin/path, 단일 POST, redirect·proxy·HTTP 재시도 금지는
유지한다. 이미 보낸 요청을 다른 주소로 재전송하지 않는다. HTTP audit hook도 유지한다.
보안 판정의 유효기간과 실제 적용 권한은 변경하지 않는다.

## 검증과 한계

- 변경 전 실제 TLS 시험 **4 FAIL**: 0.4초 요청이 header 1.282초/body 0.734초/chunk metadata
  1.266초까지 지연됐다. 21KB 헤더도 허용됐다.
- 정상 content-length/chunked/close framing과 잘못된 CA·hostname, redirect·중복 길이·잘린 본문을
  함께 검증한다. 늦은 DNS 반환 후에는 소켓이나 요청을 만들지 않는지도 확인한다.
- 확대 시험 **58 PASS, 8.16초**. 큰 trailer 시험은 최초 실패했다. 시험 peer가 요청 본문을
  모두 읽고 닫도록 고쳤고, stdlib의 trailer EOF 허용도 엄격하게 변경해 재검증했다.
- **DNS resolver 호출 자체는 Python socket API로 취소할 수 없다.** resolver 지연은 전체 예산에서
  차감하고 지연 후 접속을 거부하지만, DNS 호출이 반환하기까지의 벽시계 시간을 보장하지 않는다.
  운영 resolver의 timeout/가용성 설정과 플랫폼의 전체 작업 기한도 필요하다. detached resolver
  thread가 요청마다 누적되는 우회는 사용하지 않는다.
- stdlib `HTTPResponse`의 trailer hook을 사용하므로 Python 3.11/3.14 패키지 CI와 3.12 실제
  서비스 이미지에서 검증한다. 네트워크 장비/CNI/운영 DNS의 인수는 별도이며 이 시험은 loopback이다.

참조: [Python http.client](https://docs.python.org/3/library/http.client.html),
[socket timeout](https://docs.python.org/3/library/socket.html),
[buffered/raw I/O](https://docs.python.org/3/library/io.html).
