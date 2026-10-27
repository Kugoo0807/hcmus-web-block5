# Plan đã chốt trước khi hiện thực

## Phân rã

1. Wallet AS chịu trách nhiệm xác thực Alice/Bob, lưu client, consent, authorization code và refresh-token family.
2. Wallet API chỉ nhận access token ký ES256 và xác minh offline bằng JWKS của AS.
3. Taxi là confidential client. Browser chỉ nhận redirect kèm code; mọi token exchange và storage xảy ra ở Taxi server.
4. Script tấn công gọi AS bằng HTTP thô để tách việc kiểm protocol khỏi UI Taxi.

## Quyết định giao thức

- Grant chính là Authorization Code + PKCE S256. taxi-web dùng client_secret_basic tại token endpoint; PKCE vẫn bắt buộc vì code đi qua browser redirect.
- Client và redirect URI được kiểm chính xác trước khi AS được phép redirect. Unknown client hoặc URI sai hiển thị lỗi tại AS.
- Sau khi redirect URI hợp lệ, request sai scope hoặc thiếu PKCE được trả về client với mã OAuth và state nguyên giá trị.
- Authorization code là random opaque value. Database chỉ giữ SHA-256 hash, client binding, redirect URI, user, scope, code challenge, thời hạn và used_at.
- Code consumption dùng BEGIN IMMEDIATE và trạng thái used_at. Replay code đánh dấu access token sinh từ code đó là revoked.
- Refresh token là opaque random value; database chỉ giữ hash. Mỗi refresh sinh replacement token, đánh dấu token cũ used_at và liên kết bằng family_id. Replay token đã dùng thu hồi cả family.
- Đồng ý scope offline_access mới có refresh token. Refresh không được mở rộng scope và cần consent còn hiệu lực.
- Client Credentials chỉ được taxi-m2m dùng với rates:read. Token mang sub bằng client_id và principal_type client; không có refresh token.

## Dữ liệu và evidence

- Password Alice/Bob và client secret được bcrypt hash.
- Key ES256, client secret, session secret và encryption key được sinh vào file .env.local bị ignore.
- Taxi mã hóa refresh token AES-256-GCM và để database log khác database token.
- API ghi idempotency theo cặp user_id và idempotency key để chạy lại cùng job không trừ tiền lần hai.
- Output attack script chỉ ghi status/error đã che. Không ghi code, token, private key hay cookie.
