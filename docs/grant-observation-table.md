# Bảng grant

Bảng này là contract để đối chiếu với output thực tế của token endpoint và script. Khi nộp, đính kèm evidence/attack-results-after.json đã tạo khi chạy lab.

| Grant | refresh_token | sub | aud | scope | principal_type | expires_in |
|---|---:|---|---|---|---|---:|
| authorization_code (taxi-web, có offline_access) | Có | Wallet user id, ví dụ 1 | wallet-api | wallet:read wallet:charge offline_access | user | 120 |
| refresh_token (taxi-web) | Có, token mới thay token cũ | Wallet user id, ví dụ 1 | wallet-api | scope bằng hoặc hẹp hơn consent | user | 120 |
| client_credentials (taxi-m2m) | Không | taxi-m2m | wallet-api | rates:read | client | 120 |

Mỗi success response có access_token, token_type Bearer, expires_in và scope theo RFC 6749 section 5.1. Đây là lab nên access token có thêm JWT claims xác thực bởi Wallet API.
