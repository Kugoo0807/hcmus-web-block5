# Ma trận kiểm tra Authorization Server

| Endpoint | Kiểm tra | Sai thì trả | Chặn tấn công |
|---|---|---|---|
| /authorize | client_id đã đăng ký | Lỗi tại AS, 400, không redirect | giả mạo client |
| /authorize | redirect_uri khớp chính xác | Lỗi tại AS, 400, không redirect | đánh cắp code qua redirect URI lạ |
| /authorize | response_type là code | redirect invalid_request | request protocol sai |
| /authorize | mọi scope thuộc allowed_scopes | redirect invalid_scope | mở rộng quyền |
| /authorize | code_challenge và method S256 | redirect invalid_request | đánh cắp code ở callback |
| /consent | user phải đăng nhập | 400 tại AS | phát code không có resource owner |
| /consent | deny | redirect access_denied + state | bỏ qua consent |
| /token | HTTP Basic client authentication | 401 invalid_client | đổi code bằng secret sai |
| /token authorization_code | code tồn tại, chưa dùng, chưa hết hạn | 400 invalid_grant | code đoán/replay/hết hạn |
| /token authorization_code | client_id, redirect_uri, PKCE verifier đều khớp | 400 invalid_grant | đổi code bằng client khác hoặc verifier sai |
| /token authorization_code | consume code trong transaction | 400 invalid_grant; replay revoke access token sinh từ code | hai request song song dùng một code |
| /token refresh_token | token hash tồn tại, bound đúng client, consent active | 400 invalid_grant | refresh by another client/gỡ quyền |
| /token refresh_token | token cũ chưa used_at | 400 invalid_grant và revoke family | refresh-token replay |
| /token refresh_token | scope không rộng hơn consent/grant | 400 invalid_scope | privilege escalation |
| /token client_credentials | grant và scope thuộc client | 400 unauthorized_client hoặc invalid_scope | M2M dùng grant/scope trái phép |
