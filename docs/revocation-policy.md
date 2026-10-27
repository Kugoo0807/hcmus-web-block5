# Policy thu hồi

Alice mở Wallet AS /account sau khi đăng nhập và chọn Revoke Taxi access. AS thực hiện:

1. đặt revoked_at cho consent của user và taxi-web;
2. đặt revoked_at cho mọi refresh token trong family của user/client;
3. refresh tiếp theo của Taxi nhận invalid_grant;
4. Taxi đánh dấu linked wallet là unlinked và xóa ciphertext refresh token.

Wallet API chủ yếu xác minh access token offline bằng JWKS. Do đó access token hợp lệ trước khi Alice gỡ quyền vẫn hoạt động đến exp (tối đa 120 giây); đây là policy có chủ ý của lab. Ngoại lệ là replay authorization code: AS đánh dấu jti access token phát từ code bị replay và API lấy danh sách này để từ chối ngay. Production nên thay endpoint lab này bằng event revocation đáng tin cậy hoặc introspection theo đánh đổi độ trễ/availability.
