# hcmus-web-block5

Lab OAuth 2.0 cho Block 5: Taxi được Alice cấp quyền trừ tiền Wallet mà không biết mật khẩu ví. Repo có ba ứng dụng chạy cục bộ:

- Wallet AS: Authorization Server, đăng nhập, consent, PKCE, code exchange, refresh-token rotation, JWKS và ES256.
- Wallet API: Resource Server, tự kiểm JWT qua JWKS và thực hiện trừ tiền idempotent.
- Taxi: confidential OAuth client dùng openid-client, chỉ lưu refresh token đã mã hóa ở server và chạy payment job tuần tự.

## Yêu cầu

- Node.js 22.5 hoặc mới hơn
- npm có Internet ở lần cài đầu tiên
- Ba cổng cục bộ còn trống: 3001, 3002, 3003

## Chạy lab

1. Cài dependency.

   npm install

2. Sinh khóa ES256 và toàn bộ secret cục bộ. Lệnh này tạo các file .env.local bị gitignore; không in private key hay secret.

   npm run setup:local

3. Mở ba terminal tại thư mục repo và chạy lần lượt.

   npm run start:as
   npm run start:api
   npm run start:taxi

4. Mở http://127.0.0.1:3003, chọn Link Wallet with OAuth2, đăng nhập Wallet bằng alice / alice-password và chấp thuận consent. Taxi sẽ quay về trang chủ, sau đó có thể đọc số dư và chạy demo payment job.

5. Chạy script tấn công từ terminal thứ tư.

   npm run attacks

   Script kiểm toàn bộ trường hợp, gồm cả code hết hạn nên chờ thêm 61 giây. Khi đang phát triển nhanh có thể tạm bỏ ca hết hạn:

   npm run attacks -- --skip-expiry

   Kết quả đã che được ghi ở evidence/attack-results-after.json. Script không in code, access token, refresh token hoặc cookie.

## Endpoint và contract

Wallet AS là http://127.0.0.1:3001. Access token là JWT ES256, có iss là Wallet AS, aud là wallet-api, sub, client_id, scope, exp, jti và principal_type. Code sống 60 giây, access token sống 120 giây, refresh token sống 7 ngày.

Wallet API:

- GET /wallet/balance: cần wallet:read và principal_type user.
- POST /wallet/charges: cần wallet:charge, principal_type user và Idempotency-Key.
- GET /public/rates: cần rates:read; token M2M được chấp nhận.

Wallet AS đăng ký sẵn:

- taxi-web: authorization_code và refresh_token, redirect URI chính xác là http://127.0.0.1:3003/oauth/callback.
- taxi-m2m: chỉ client_credentials và chỉ rates:read.

## Cấu trúc source

- apps/wallet-as/src/server.mjs: Authorization Server và schema của users, clients, auth_codes, consents, refresh_tokens.
- apps/wallet-api/src/server.mjs: xác thực JWT bằng JWKS, số dư, charge counter và idempotency.
- apps/taxi/src/server.mjs: luồng client OAuth, kho refresh token AES-256-GCM và log job tách database.
- scripts/generate-local-config.mjs: sinh key/secret local.
- scripts/attack-tests.mjs: gọi thẳng AS/API cho các case phải bị từ chối.
- docs/: plan, ma trận kiểm tra, grant table, policy thu hồi.
- evidence/: nơi chứa output đã che; không commit secret/token.

## Ghi chú an toàn

Đây là AS phục vụ lab, không phải hệ thống production. Phiên được lưu trong memory store, dữ liệu SQLite cục bộ, và endpoint danh sách jti bị thu hồi chỉ mô phỏng sự kiện thu hồi sau code replay. Production nên dùng một Authorization Server đã được kiểm chứng, một session store bền vững, key management/HSM, audit log, rate limit, TLS, monitoring và cơ chế introspection hoặc event revocation chuẩn.
