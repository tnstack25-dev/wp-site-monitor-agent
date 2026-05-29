=== WP Site Monitor Agent ===
Contributors: tnstack
Tags: monitor, security, malware scan, agent
Requires at least: 5.8
Tested up to: 6.6
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Child agent for WP Site Monitor Manager.

== Description ==

WP Site Monitor Agent exposes signed REST endpoints for WP Site Monitor Manager.
It supports remote health checks and remote malware scanning on the child site's own WordPress source files.
It also includes an admin access log viewer for tailing the configured web server access log.
Updates are managed through GitHub Releases.

== Installation ==

1. Upload the plugin to the child WordPress site.
2. Activate WP Site Monitor Agent.
3. Open Settings > WP Site Monitor Agent.
4. Set the Agent secret.
5. Use the same value as Backup Secret for this site in WP Site Monitor Manager.
6. Optional: configure Access log path to view recent access log lines in wp-admin.
7. For daily log files, use placeholders such as `/var/log/nginx/example.com-{Y-m-d}.access.log`.

== Changelog ==

= 1.0.0 =
Initial production baseline for WP Site Monitor Manager child-agent mode.
