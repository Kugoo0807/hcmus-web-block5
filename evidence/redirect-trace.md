# Trace redirect đã che

Trace này được quan sát khi chạy scripts/smoke-taxi-flow.mjs. Giá trị bí mật được thay bằng nhãn.

1. Browser GET Taxi /link-wallet.
2. Taxi trả 302 đến Wallet AS /authorize với client_id=taxi-web, redirect_uri=http://127.0.0.1:3003/oauth/callback, scope=wallet:read wallet:charge offline_access, code_challenge=REDACTED và state=REDACTED.
3. Wallet AS trả 302 /login; browser gửi session cookie chỉ tới Wallet AS.
4. Sau khi Alice đăng nhập và Allow, Wallet AS trả 302 đến Taxi /oauth/callback?code=REDACTED&state=REDACTED.
5. Taxi kiểm state và gửi code, redirect URI, code_verifier=REDACTED cùng Basic client authentication tới /token từ server.
6. Browser được trả về Taxi /. Không có access token hay refresh token trong URL, HTML, cookie trình duyệt hoặc log.
