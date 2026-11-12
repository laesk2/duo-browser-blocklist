# Duo Browser 차단 목록

iPhone Duo용 브라우저 [Duo Browser](https://insidious-camp-df8.notion.site/Duo-Browser-415ef239cf5480fca57ac3ce280e515b)가 쓰는 광고·추적 차단 목록입니다.

- `domains.txt`: 사람이 고치는 목록 (도메인 또는 도메인/경로)
- `dist/blocklist.json`, `dist/blocklist.json.sig`: GitHub Actions가 검사하고 Ed25519로 서명한 결과
- `signing-public-key.txt`: 서명 확인용 공개 키 (앱에 들어 있는 것과 같음). 매일 이 키로 올린 파일의 서명을 다시 확인합니다.

앱은 하루에 한 번 이 파일만 받습니다. 서명이 맞고 버전이 더 새로울 때만 적용하며, 목록에는 "막을 주소"만 들어갈 수 있습니다(허용·페이지 변경 규칙 없음). 앱은 방문 기록·검색어 같은 정보를 보내지 않습니다. 다만 파일을 받을 때 GitHub 서버가 접속한 IP 주소를 알 수 있습니다.

잘못 막히는 사이트가 있으면 이슈로 알려 주세요.
