# Evidence

- attack-results-after.json được scripts/attack-tests.mjs sinh sau khi AS và API chạy. File chỉ chứa status và OAuth error, không chứa secret hoặc token.
- Để có evidence baseline theo yêu cầu buổi học, chạy cùng script trên branch/commit có đánh dấu tạm thời các validation chưa hiện thực và lưu output thành attack-results-before.json. Không đưa source baseline yếu vào nhánh nộp.
- Trace redirect nên che toàn bộ giá trị code và state. Log Taxi đã hiển thị exp của access token và charge_count mà không log token.
