# Evidence payment job đã che

Lần chạy smoke test ghi một bản ghi ở database log tách với database refresh token.

| Trường | Giá trị quan sát |
|---|---|
| created_at | 2026-10-27T16:59:54.851Z |
| user_id | 1 |
| status | charged |
| access_exp | 2026-10-27T17:01:54.000Z |
| charge_count | 1 |
| idempotent_replay | false |

Job dùng Idempotency-Key ổn định theo user và ngày. Chạy lại cùng ngày trả idempotent_replay=true thay vì trừ tiền thêm lần nữa. Log không chứa authorization code, access token, refresh token hoặc cookie.
