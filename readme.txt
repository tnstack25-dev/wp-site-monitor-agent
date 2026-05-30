=== WP Site Monitor Agent ===
Contributors: tnstack
Tags: monitor, health check, access log, agent
Requires at least: 5.8
Tested up to: 6.6
Requires PHP: 7.4
Stable tag: 2.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Child agent for WP Site Monitor Manager.

== Description ==

WP Site Monitor Agent exposes a health status endpoint for WP Site Monitor Manager.
It also includes an admin access log viewer for tailing the configured web server access log.
Updates are managed through GitHub Releases.

== Installation ==

1. Upload the plugin to the child WordPress site.
2. Activate WP Site Monitor Agent.
3. Open WP Site Monitor Agent in the admin sidebar.
4. Copy the Manager connection key into the website configuration in WP Site Monitor Manager.
5. Optional: enable signed one-click SSO and select the only administrator allowed to receive login tickets.
6. Optional: configure Access log path to view recent access log lines in wp-admin.
7. For daily log files, use placeholders such as `/var/log/nginx/example.com-{Y-m-d}.access.log`.
8. In Account permissions, select the users allowed to access the Agent and grant only the required permissions.

== Account permissions ==

The Agent page supports an explicit allowlist. Permissions are independent: an account may receive plugin management permissions without being allowed to open the Agent menu.

* Access Agent: allows opening the Agent page.
* View log files: allows viewing the configured access log file.
* Edit Agent settings: allows editing Agent configuration.
* Manage plugins: grants WordPress plugin activate, update, and delete capabilities.
* Install plugins: grants the WordPress plugin installation and ZIP upload capabilities.
* Manage themes: grants WordPress theme switching, options, update, and delete capabilities.
* Edit plugin/theme files: grants WordPress plugin and theme file editor capabilities. Enable this only for trusted users and only when required.

At least one administrator must retain Access Agent and Edit Agent settings permissions to prevent configuration lockout.

When Quick login SSO is enabled, the selected administrator account cannot be deleted. Disable SSO or select another administrator before deleting that account.

== Changelog ==

= 2.0.0 =
Added production security hardening, signed Manager communication, restricted SSO, account permission management, theme management permissions, protected SSO accounts, and the redesigned Agent admin interface.

= 1.0.3 =
Added per-site HMAC authentication, replay protection, signed inventory requests, and opt-in restricted SSO.

= 1.0.2 =
Removed backup and malware scan modules. Retained health status and access log viewer.
