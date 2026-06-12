=== WP Site Monitor Agent ===
Contributors: tnstack
Tags: monitor, health check, access log, agent
Requires at least: 5.8
Tested up to: 6.6
Requires PHP: 7.4
Stable tag: 2.1.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Agent con dành cho WP Site Monitor Manager.

== Description ==

WP Site Monitor Agent cung cấp điểm kết nối trạng thái hoạt động cho WP Site Monitor Manager.
Plugin cũng có trình xem các dòng gần nhất trong nhật ký truy cập của máy chủ web đã cấu hình.
Các bản cập nhật được quản lý thông qua GitHub Releases.

== Installation ==

1. Tải plugin lên website WordPress con.
2. Kích hoạt WP Site Monitor Agent.
3. Mở WP Site Monitor Agent trong thanh bên quản trị.
4. Sao chép khóa kết nối Manager vào cấu hình website tương ứng trong WP Site Monitor Manager.
5. Tùy chọn: bật đăng nhập nhanh SSO đã ký và chọn duy nhất một quản trị viên được phép nhận liên kết đăng nhập.
6. Tùy chọn: cấu hình đường dẫn nhật ký truy cập để xem các dòng gần nhất trong wp-admin.
7. Với tệp nhật ký theo ngày, dùng các biến như `/var/log/nginx/example.com-{Y-m-d}.access.log`.
8. Trong phần phân quyền tài khoản, chọn người dùng được phép truy cập Agent và chỉ cấp các quyền cần thiết.

== Account permissions ==

Trang Agent hỗ trợ danh sách tài khoản được phép truy cập. Các quyền hoạt động độc lập: một tài khoản có thể nhận quyền quản lý plugin mà không được phép mở menu Agent.

* Truy cập Agent: cho phép mở trang Agent.
* Xem tệp nhật ký: cho phép xem tệp nhật ký truy cập đã cấu hình.
* Sửa cài đặt Agent: cho phép chỉnh sửa cấu hình Agent.
* Quản lý plugin: cấp quyền kích hoạt, cập nhật và xóa plugin WordPress.
* Cài plugin: cấp quyền cài plugin WordPress và tải tệp ZIP lên.
* Quản lý giao diện: cấp quyền chuyển đổi, tùy chỉnh, cập nhật và xóa giao diện WordPress.
* Sửa tệp plugin/giao diện: cấp quyền dùng trình sửa tệp plugin và giao diện của WordPress. Chỉ bật cho tài khoản tin cậy và khi thực sự cần thiết.

Ít nhất một quản trị viên phải giữ quyền truy cập Agent và sửa cài đặt Agent để tránh mất quyền truy cập cấu hình.

Khi đăng nhập nhanh SSO đang bật, tài khoản quản trị viên được chọn không thể bị xóa. Hãy tắt SSO hoặc chọn quản trị viên khác trước khi xóa tài khoản đó.

== Changelog ==

= 2.1.1 =
Bổ sung access log production và bảo vệ khóa kết nối Manager bằng bước xác nhận mật khẩu WordPress hiện tại.

= 2.1.0 =
Chuẩn hóa văn bản tiếng Việt và cải thiện tài liệu hướng dẫn Agent.

= 2.0.2 =
Cập nhật khả năng tương thích của gói release với cơ chế cập nhật plugin WordPress.

= 2.0.0 =
Bổ sung bảo mật cho môi trường production, giao tiếp Manager có chữ ký, giới hạn SSO, quản lý quyền tài khoản, quyền quản lý giao diện, bảo vệ tài khoản SSO và thiết kế lại giao diện quản trị Agent.

= 1.0.3 =
Bổ sung xác thực HMAC theo từng website, chống phát lại yêu cầu, yêu cầu tải thông tin kỹ thuật có chữ ký và tùy chọn giới hạn SSO.

= 1.0.2 =
Loại bỏ các mô-đun sao lưu và quét mã độc. Giữ lại trạng thái hoạt động và trình xem nhật ký truy cập.
