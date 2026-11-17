# Duo Browser 차단 목록

iPhone Duo용 브라우저 [Duo Browser](https://insidious-camp-df8.notion.site/Duo-Browser-415ef239cf5480fca57ac3ce280e515b)가 쓰는 광고·추적 차단 목록입니다.

- `domains.txt`: 사람이 고치는 목록 (도메인 또는 도메인/경로). 한국 광고·추적 도메인 등
- `tracking-params.txt`: 링크 주소에서 지울 추적 값 이름 (`utm_*`는 앱이 늘 지운다)
- `scripts/convert.py`: 공개 차단 목록(Adblock Plus 문법)을 바꾼다. 막기·예외·요소 숨기기만 만들고, 바꿀 수 없는 문법(스크립트 주입, 원시 정규식 등)은 버린다
- `dist/blocklist-v2.json`(+`.sig`, `.version`): 빌드 42부터 쓰는 형식 2. 공개 목록 + 위 두 파일. GitHub Actions가 매일 받아 검사하고 Ed25519로 서명한다(공개 목록만 바뀐 것은 3일에 한 번)
- `dist/blocklist.json`(+`.sig`): 빌드 41까지 쓰는 형식 1 (`domains.txt`만)
- `signing-public-key.txt`: 서명 확인용 공개 키 (앱에 들어 있는 것과 같음). 매일 이 키로 올린 파일의 서명을 다시 확인합니다.

앱은 하루에 한 번 `.version` 파일(몇 바이트)을 받아 보고, 새 버전일 때만 목록을 받습니다. 서명이 맞고 버전이 더 새로울 때만 적용하며, 앱이 항목을 하나씩 다시 검사해 규칙을 직접 만듭니다(막기·막기의 예외·요소 숨기기만, 스크립트·페이지 변경 없음). 앱은 방문 기록·검색어 같은 정보를 보내지 않습니다. 다만 파일을 받을 때 GitHub 서버가 접속한 IP 주소를 알 수 있습니다.

## 출처와 라이선스

`dist/blocklist-v2.json`에는 다음 공개 목록을 바꾼 내용이 들어 있습니다.

| 목록 | 만든 곳 | 라이선스 |
|---|---|---|
| EasyList | The EasyList authors (https://easylist.to/) | GPLv3 이상 또는 CC BY-SA 3.0 중 CC BY-SA 3.0으로 씀 |
| EasyPrivacy | The EasyList authors (https://easylist.to/) | 위와 같음 |
| EasyList Cookie List | The EasyList authors (https://easylist.to/) | CC BY 3.0 |

그래서 `dist/blocklist-v2.json`과 이 저장소의 목록 파일은 [CC BY-SA 3.0](https://creativecommons.org/licenses/by-sa/3.0/)으로 배포합니다. 바꾼 내용: Adblock Plus 문법을 WebKit 콘텐츠 규칙에 맞게 바꾸고, 바꿀 수 없는 규칙은 뺐습니다.

잘못 막히는 사이트가 있으면 이슈로 알려 주세요.
