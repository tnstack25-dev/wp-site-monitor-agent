<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPMA_Plugin {
	const OPTION          = 'wpma_settings';
	const INVENTORY_CACHE = 'wpma_inventory_cache';
	const INVENTORY_INTERVAL = 6 * HOUR_IN_SECONDS;

	public static function init() {
		add_action( 'admin_init', array( __CLASS__, 'maybe_upgrade' ) );
		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'handle_settings_save' ) );
		add_action( 'admin_notices', array( __CLASS__, 'show_notice' ) );
		add_filter( 'all_plugins', array( __CLASS__, 'hide_from_plugins_list' ) );
		add_action( 'rest_api_init', array( __CLASS__, 'register_rest_routes' ) );
	}

	public static function defaults() {
		return array(
			'secret'          => '',
			'hide_agent'      => 0,
			'access_log_path' => '',
			'log_lines'       => 200,
		);
	}

	public static function settings() {
		$settings = get_option( self::OPTION, array() );
		$settings = wp_parse_args( is_array( $settings ) ? $settings : array(), self::defaults() );
		$settings['hide_agent'] = ! empty( $settings['hide_agent'] ) ? 1 : 0;
		$settings['access_log_path'] = isset( $settings['access_log_path'] ) ? (string) $settings['access_log_path'] : '';
		$settings['log_lines'] = min( 1000, max( 20, absint( $settings['log_lines'] ) ) );
		return $settings;
	}

	public static function activate() {
		update_option( 'wpma_plugin_version', WPMA_VERSION, false );
	}

	public static function deactivate() {
		// No scheduled tasks are required. The manager calls this agent on demand.
	}

	public static function maybe_upgrade() {
		if ( get_option( 'wpma_plugin_version' ) === WPMA_VERSION ) {
			return;
		}

		$settings = get_option( self::OPTION, array() );
		if ( is_array( $settings ) ) {
			$settings = wp_parse_args( $settings, self::defaults() );
			$settings = array(
				'secret'          => isset( $settings['secret'] ) ? (string) $settings['secret'] : '',
				'hide_agent'      => ! empty( $settings['hide_agent'] ) ? 1 : 0,
				'access_log_path' => isset( $settings['access_log_path'] ) ? self::sanitize_log_path( $settings['access_log_path'] ) : '',
				'log_lines'       => isset( $settings['log_lines'] ) ? min( 1000, max( 20, absint( $settings['log_lines'] ) ) ) : 200,
			);
			update_option( self::OPTION, $settings, false );
		}

		update_option( 'wpma_plugin_version', WPMA_VERSION, false );
	}

	public static function register_rest_routes() {
		register_rest_route(
			'wpma/v1',
			'/status',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'rest_status' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			'wpma/v1',
			'/malware-scan',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'rest_malware_scan' ),
				'permission_callback' => array( __CLASS__, 'verify_rest_signature' ),
			)
		);

		register_rest_route(
			'wpma/v1',
			'/backup',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'rest_create_backup' ),
				'permission_callback' => array( __CLASS__, 'verify_rest_signature' ),
			)
		);

		register_rest_route(
			'wpma/v1',
			'/backup-download/(?P<token>[A-Za-z0-9_-]{32,80})',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'rest_download_backup' ),
				'permission_callback' => array( __CLASS__, 'verify_backup_download_signature' ),
			)
		);
	}

	public static function rest_status() {
		return rest_ensure_response(
			array(
				'success'        => true,
				'agent'          => 'wp-site-monitor-agent',
				'agent_version'  => WPMA_VERSION,
				'site_url'       => home_url( '/' ),
				'wp_version'     => get_bloginfo( 'version' ),
				'php_version'    => PHP_VERSION,
				'secret_configured' => self::settings()['secret'] !== '',
			)
		);
	}

	public static function verify_rest_signature( $request ) {
		$settings = self::settings();
		if ( empty( $settings['secret'] ) ) {
			return new WP_Error( 'wpma_missing_secret', 'Agent secret is not configured.', array( 'status' => 403 ) );
		}

		$time = (int) $request->get_header( 'x-wpsmm-time' );
		$signature = (string) $request->get_header( 'x-wpsmm-signature' );
		$body = (string) $request->get_body();
		if ( ! $time || ! $signature || abs( time() - $time ) > 300 ) {
			return new WP_Error( 'wpma_bad_signature', 'Invalid or expired scan signature.', array( 'status' => 403 ) );
		}

		$expected = hash_hmac( 'sha256', $time . '.' . $body, $settings['secret'] );
		if ( ! hash_equals( $expected, $signature ) ) {
			return new WP_Error( 'wpma_bad_signature', 'Invalid scan signature.', array( 'status' => 403 ) );
		}

		return true;
	}

	public static function rest_malware_scan( $request ) {
		$params = json_decode( (string) $request->get_body(), true );
		$params = is_array( $params ) ? $params : array();
		$result = self::scan_malware_path(
			ABSPATH,
			max( 500, absint( $params['max_files'] ?? 7000 ) ),
			max( 50, absint( $params['max_findings'] ?? 500 ) )
		);

		return rest_ensure_response(
			array(
				'success'          => empty( $result['error'] ),
				'site_url'         => home_url( '/' ),
				'scanned_files'    => (int) $result['scanned'],
				'suspicious_count' => count( $result['findings'] ),
				'findings'         => $result['findings'],
				'message'          => empty( $result['error'] ) ? 'Remote scan complete.' : $result['error'],
			)
		);
	}

	public static function rest_create_backup() {
		$result = self::create_source_backup();
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$token = wp_generate_password( 48, false, false );
		set_transient(
			'wpma_backup_' . $token,
			array(
				'path' => $result['path'],
				'name' => $result['name'],
				'size' => $result['size'],
			),
			10 * MINUTE_IN_SECONDS
		);

		return rest_ensure_response(
			array(
				'success'      => true,
				'site_url'     => home_url( '/' ),
				'token'        => $token,
				'file_name'    => $result['name'],
				'file_size'    => $result['size'],
				'download_url' => rest_url( 'wpma/v1/backup-download/' . $token ),
			)
		);
	}

	public static function verify_backup_download_signature( $request ) {
		$settings = self::settings();
		$token = (string) $request['token'];
		$time = (int) $request->get_header( 'x-wpsmm-time' );
		$signature = (string) $request->get_header( 'x-wpsmm-signature' );
		if ( empty( $settings['secret'] ) || ! $time || ! $signature || abs( time() - $time ) > 300 ) {
			return new WP_Error( 'wpma_bad_signature', 'Invalid or expired backup download signature.', array( 'status' => 403 ) );
		}

		$expected = hash_hmac( 'sha256', $time . '.' . $token, $settings['secret'] );
		return hash_equals( $expected, $signature )
			? true
			: new WP_Error( 'wpma_bad_signature', 'Invalid backup download signature.', array( 'status' => 403 ) );
	}

	public static function rest_download_backup( $request ) {
		$token = (string) $request['token'];
		$data = get_transient( 'wpma_backup_' . $token );
		$path = is_array( $data ) ? (string) ( $data['path'] ?? '' ) : '';
		if ( ! self::backup_path_allowed( $path ) || ! is_readable( $path ) ) {
			return new WP_Error( 'wpma_backup_missing', 'Backup file is missing or expired.', array( 'status' => 404 ) );
		}

		while ( ob_get_level() ) {
			ob_end_clean();
		}
		ignore_user_abort( true );
		nocache_headers();
		header( 'Content-Type: application/zip' );
		header( 'Content-Disposition: attachment; filename="' . basename( $path ) . '"' );
		header( 'Content-Length: ' . filesize( $path ) );
		header( 'X-Content-Type-Options: nosniff' );
		$bytes = readfile( $path );
		if ( false !== $bytes && $bytes > 0 ) {
			delete_transient( 'wpma_backup_' . $token );
			@unlink( $path );
		}
		exit;
	}

	private static function create_source_backup() {
		if ( ! class_exists( 'ZipArchive' ) ) {
			return new WP_Error( 'wpma_zip_missing', 'ZipArchive is not available on the child site.', array( 'status' => 500 ) );
		}

		$dir = self::prepare_backup_dir();
		if ( ! is_dir( $dir ) || ! is_writable( $dir ) ) {
			return new WP_Error( 'wpma_backup_dir', 'Child backup directory is not writable.', array( 'status' => 500 ) );
		}

		$name = 'wpma-source-' . gmdate( 'Ymd-His' ) . '-' . wp_generate_password( 16, false, false ) . '.zip';
		$path = $dir . $name;
		$zip = new ZipArchive();
		if ( true !== $zip->open( $path, ZipArchive::CREATE | ZipArchive::OVERWRITE ) ) {
			return new WP_Error( 'wpma_zip_create', 'Cannot create the child backup ZIP.', array( 'status' => 500 ) );
		}

		$root = ABSPATH;
		$exclude = array( 'wp-content/uploads/wpsma-backups' );
		$added_files = 0;
		$added_dirs = 0;
		$failed = array();
		try {
			$files = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);
			foreach ( $files as $file ) {
				$relative = ltrim( str_replace( $root, '', $file->getPathname() ), '/\\' );
				$normalized = str_replace( '\\', '/', $relative );
				foreach ( $exclude as $excluded ) {
					if ( $normalized === $excluded || 0 === strpos( $normalized, trailingslashit( $excluded ) ) ) {
						continue 2;
					}
				}
				if ( $file->isDir() ) {
					if ( ! $zip->addEmptyDir( $relative ) ) {
						$failed[] = $normalized;
					}
					$added_dirs++;
				} elseif ( $file->isFile() ) {
					if ( ! is_readable( $file->getPathname() ) || ! $zip->addFile( $file->getPathname(), $relative ) ) {
						$failed[] = $normalized;
					}
					$added_files++;
				}
			}
		} catch ( Throwable $e ) {
			$zip->close();
			@unlink( $path );
			return new WP_Error( 'wpma_zip_read', 'Cannot read the complete child site filesystem: ' . $e->getMessage(), array( 'status' => 500 ) );
		}
		$zip->addFromString(
			'wpma-backup-info.json',
			wp_json_encode(
				array(
					'created_at'  => current_time( 'mysql' ),
					'site'        => home_url( '/' ),
					'added_files' => $added_files,
					'added_dirs'  => $added_dirs,
					'failed'      => $failed,
				),
				JSON_PRETTY_PRINT
			)
		);
		if ( ! $zip->close() || ! is_file( $path ) ) {
			@unlink( $path );
			return new WP_Error( 'wpma_zip_close', 'Cannot finalize the child backup ZIP.', array( 'status' => 500 ) );
		}
		if ( ! empty( $failed ) ) {
			@unlink( $path );
			return new WP_Error( 'wpma_zip_incomplete', 'Backup stopped because some source files could not be added: ' . implode( ', ', array_slice( $failed, 0, 5 ) ), array( 'status' => 500 ) );
		}

		return array( 'path' => $path, 'name' => $name, 'size' => filesize( $path ) );
	}

	private static function prepare_backup_dir() {
		$upload = wp_upload_dir();
		$dir = trailingslashit( $upload['basedir'] ) . 'wpsma-backups/';
		wp_mkdir_p( $dir );
		if ( is_dir( $dir ) ) {
			if ( ! file_exists( $dir . '.htaccess' ) ) {
				file_put_contents( $dir . '.htaccess', "Require all denied\nDeny from all\n" );
			}
			if ( ! file_exists( $dir . 'web.config' ) ) {
				file_put_contents( $dir . 'web.config', "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n" );
			}
			if ( ! file_exists( $dir . 'index.php' ) ) {
				file_put_contents( $dir . 'index.php', "<?php\n// Silence is golden.\n" );
			}
			foreach ( glob( $dir . '*.zip' ) ?: array() as $file ) {
				if ( is_file( $file ) && filemtime( $file ) < time() - HOUR_IN_SECONDS ) {
					@unlink( $file );
				}
			}
		}
		return $dir;
	}

	private static function backup_path_allowed( $path ) {
		$upload = wp_upload_dir();
		$base = realpath( trailingslashit( $upload['basedir'] ) . 'wpsma-backups/' );
		$real = realpath( $path );
		return $base && $real && 0 === strpos( $real, trailingslashit( $base ) );
	}

	public static function is_hidden() {
		if ( defined( 'WPMA_FORCE_VISIBLE' ) && WPMA_FORCE_VISIBLE ) {
			return false;
		}
		return ! empty( self::settings()['hide_agent'] );
	}

	public static function admin_menu() {
		if ( self::is_hidden() ) {
			return;
		}

		add_menu_page(
			__( 'WP Site Monitor Agent', 'wp-site-monitor-agent' ),
			__( 'WP Site Monitor Agent', 'wp-site-monitor-agent' ),
			'manage_options',
			'wp-site-monitor-agent',
			array( __CLASS__, 'render_settings_page' ),
			'dashicons-shield-alt',
			59
		);
	}

	public static function hide_from_plugins_list( $plugins ) {
		if ( self::is_hidden() && isset( $plugins[ plugin_basename( WPMA_PLUGIN_FILE ) ] ) ) {
			unset( $plugins[ plugin_basename( WPMA_PLUGIN_FILE ) ] );
		}
		return $plugins;
	}

	public static function handle_settings_save() {
		if ( ! current_user_can( 'manage_options' ) || empty( $_POST['wpma_save_settings'] ) ) {
			return;
		}

		check_admin_referer( 'wpma_save_settings', 'wpma_nonce' );
		$current = self::settings();
		$new_secret = isset( $_POST['secret'] ) ? sanitize_text_field( wp_unslash( $_POST['secret'] ) ) : '';
		$settings = array(
			'secret'          => '' !== $new_secret ? $new_secret : $current['secret'],
			'hide_agent'      => ! empty( $_POST['hide_agent'] ) ? 1 : 0,
			'access_log_path' => isset( $_POST['access_log_path'] ) ? self::sanitize_log_path( wp_unslash( $_POST['access_log_path'] ) ) : '',
			'log_lines'       => isset( $_POST['log_lines'] ) ? min( 1000, max( 20, absint( $_POST['log_lines'] ) ) ) : 200,
		);

		update_option( self::OPTION, $settings, false );
		if ( class_exists( 'WPMA_GitHub_Updater' ) ) {
			WPMA_GitHub_Updater::clear_cache();
		}
		add_settings_error( 'wpma_messages', 'wpma_saved', __( 'Agent settings saved.', 'wp-site-monitor-agent' ), 'updated' );
	}

	public static function render_settings_page() {
		$settings = self::settings();
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'WP Site Monitor Agent', 'wp-site-monitor-agent' ); ?></h1>
			<p><?php esc_html_e( 'This child agent serves WP Site Monitor Manager. It exposes signed endpoints for remote source backups, malware scanning, and health checks.', 'wp-site-monitor-agent' ); ?></p>
			<?php settings_errors( 'wpma_messages' ); ?>
			<form method="post" action="">
				<?php wp_nonce_field( 'wpma_save_settings', 'wpma_nonce' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th><label for="secret"><?php esc_html_e( 'Agent secret', 'wp-site-monitor-agent' ); ?></label></th>
						<td>
							<input name="secret" id="secret" type="password" class="regular-text" value="" autocomplete="new-password" placeholder="<?php esc_attr_e( 'Leave blank to keep current secret', 'wp-site-monitor-agent' ); ?>">
							<?php if ( ! empty( $settings['secret'] ) ) : ?>
								<p class="description"><?php esc_html_e( 'A secret is saved. Use the same value as Backup Secret for this site in WP Site Monitor Manager.', 'wp-site-monitor-agent' ); ?></p>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Agent endpoint', 'wp-site-monitor-agent' ); ?></th>
						<td>
							<code><?php echo esc_html( rest_url( 'wpma/v1/malware-scan' ) ); ?></code>
							<p class="description"><?php esc_html_e( 'The manager calls this endpoint with an HMAC signature. It is not intended for manual use.', 'wp-site-monitor-agent' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Visibility', 'wp-site-monitor-agent' ); ?></th>
						<td>
							<label><input type="checkbox" name="hide_agent" value="1" <?php checked( $settings['hide_agent'] ); ?>> <?php esc_html_e( 'Hide this agent from the Plugins list and Settings menu', 'wp-site-monitor-agent' ); ?></label>
						</td>
					</tr>
					<tr>
						<th><label for="access_log_path"><?php esc_html_e( 'Access log path', 'wp-site-monitor-agent' ); ?></label></th>
						<td>
							<input name="access_log_path" id="access_log_path" type="text" class="large-text code" value="<?php echo esc_attr( $settings['access_log_path'] ); ?>" placeholder="/var/log/nginx/example.com-{Y-m-d}.access.log">
							<p class="description"><?php esc_html_e( 'Absolute path or date pattern. Supported placeholders: {date}, {Y-m-d}, {Ymd}, {Y}, {m}, {d}. The file must be readable by PHP.', 'wp-site-monitor-agent' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><label for="log_lines"><?php esc_html_e( 'Lines to show', 'wp-site-monitor-agent' ); ?></label></th>
						<td>
							<input name="log_lines" id="log_lines" type="number" min="20" max="1000" step="20" value="<?php echo esc_attr( $settings['log_lines'] ); ?>">
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save Agent Settings', 'wp-site-monitor-agent' ), 'primary', 'wpma_save_settings' ); ?>
			</form>
			<?php self::render_log_viewer( $settings ); ?>
		</div>
		<?php
	}

	public static function show_notice() {
		if ( empty( $_GET['page'] ) || 'wp-site-monitor-agent' !== $_GET['page'] ) {
			return;
		}
		settings_errors( 'wpma_messages' );
	}

	private static function render_log_viewer( $settings ) {
		$selected_date = self::selected_log_date();
		$path = self::resolve_log_path( (string) $settings['access_log_path'], $selected_date );
		$lines = (int) $settings['log_lines'];
		$status = self::log_status( $path );
		?>
		<hr>
		<h2><?php esc_html_e( 'Access Log Viewer', 'wp-site-monitor-agent' ); ?></h2>
		<p><?php esc_html_e( 'Shows the latest lines from the configured access log without opening the hosting control panel.', 'wp-site-monitor-agent' ); ?></p>
		<form method="get" action="<?php echo esc_url( admin_url( 'admin.php' ) ); ?>" style="display:flex;gap:10px;align-items:end;flex-wrap:wrap;margin:12px 0;">
			<input type="hidden" name="page" value="wp-site-monitor-agent">
			<label><?php esc_html_e( 'Log date', 'wp-site-monitor-agent' ); ?><br>
				<input type="date" name="wpma_log_date" value="<?php echo esc_attr( $selected_date ); ?>">
			</label>
			<?php submit_button( __( 'View date', 'wp-site-monitor-agent' ), 'secondary', '', false ); ?>
		</form>
		<?php if ( '' === $path ) : ?>
			<div class="notice notice-info inline"><p><?php esc_html_e( 'Configure an access log path above, then save settings.', 'wp-site-monitor-agent' ); ?></p></div>
		<?php elseif ( is_wp_error( $status ) ) : ?>
			<div class="notice notice-error inline"><p><?php echo esc_html( $status->get_error_message() ); ?></p></div>
		<?php else : ?>
			<p>
				<strong><?php esc_html_e( 'File:', 'wp-site-monitor-agent' ); ?></strong>
				<code><?php echo esc_html( $path ); ?></code>
				<a class="button button-small" href="<?php echo esc_url( add_query_arg( array( 'page' => 'wp-site-monitor-agent', 'wpma_log_date' => $selected_date, 'wpma_log_refresh' => time() ), admin_url( 'admin.php' ) ) ); ?>"><?php esc_html_e( 'Refresh', 'wp-site-monitor-agent' ); ?></a>
			</p>
			<pre style="max-height:520px;overflow:auto;background:#101827;color:#e5eefb;padding:16px;border-radius:8px;white-space:pre-wrap;"><?php echo esc_html( self::read_log_tail( $path, $lines ) ); ?></pre>
		<?php endif; ?>
		<?php
	}

	private static function log_status( $path ) {
		if ( '' === trim( (string) $path ) ) {
			return new WP_Error( 'wpma_log_empty', 'Access log path is empty.' );
		}
		if ( false !== strpos( (string) $path, "\0" ) ) {
			return new WP_Error( 'wpma_log_invalid', 'Access log path is invalid.' );
		}
		if ( ! is_file( $path ) ) {
			return new WP_Error( 'wpma_log_missing', 'Access log file does not exist.' );
		}
		if ( ! is_readable( $path ) ) {
			return new WP_Error( 'wpma_log_unreadable', 'Access log file is not readable by PHP.' );
		}
		return true;
	}

	private static function sanitize_log_path( $path ) {
		$path = trim( sanitize_text_field( (string) $path ) );
		if ( false !== strpos( $path, "\0" ) ) {
			return '';
		}
		return wp_normalize_path( $path );
	}

	private static function selected_log_date() {
		$value = isset( $_GET['wpma_log_date'] ) ? sanitize_text_field( wp_unslash( $_GET['wpma_log_date'] ) ) : wp_date( 'Y-m-d' );
		if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $value ) ) {
			return wp_date( 'Y-m-d' );
		}
		return $value;
	}

	private static function resolve_log_path( $pattern, $date ) {
		$pattern = trim( (string) $pattern );
		if ( '' === $pattern ) {
			return '';
		}

		$timestamp = strtotime( $date . ' 00:00:00' );
		if ( ! $timestamp ) {
			$timestamp = time();
		}

		$replacements = array(
			'{date}'  => gmdate( 'Y-m-d', $timestamp ),
			'{Y-m-d}' => gmdate( 'Y-m-d', $timestamp ),
			'{Ymd}'   => gmdate( 'Ymd', $timestamp ),
			'{Y}'     => gmdate( 'Y', $timestamp ),
			'{m}'     => gmdate( 'm', $timestamp ),
			'{d}'     => gmdate( 'd', $timestamp ),
		);

		return strtr( $pattern, $replacements );
	}

	private static function read_log_tail( $path, $lines ) {
		$status = self::log_status( $path );
		if ( is_wp_error( $status ) ) {
			return $status->get_error_message();
		}

		$max_bytes = 512 * 1024;
		$size = filesize( $path );
		if ( false === $size || 0 === $size ) {
			return '';
		}

		$handle = fopen( $path, 'rb' );
		if ( ! $handle ) {
			return 'Cannot open log file.';
		}

		$offset = max( 0, $size - $max_bytes );
		fseek( $handle, $offset );
		$content = (string) fread( $handle, $max_bytes );
		fclose( $handle );

		$content = preg_replace( "/\r\n?/", "\n", $content );
		$rows = explode( "\n", trim( $content ) );
		$rows = array_slice( $rows, -1 * max( 20, absint( $lines ) ) );
		return implode( "\n", $rows );
	}

	public static function get_inventory() {
		$cached = get_option( self::INVENTORY_CACHE, array() );
		$last_run = isset( $cached['last_run'] ) ? absint( $cached['last_run'] ) : 0;
		if ( $last_run && ( time() - $last_run ) < self::INVENTORY_INTERVAL && ! empty( $cached['summary'] ) ) {
			return $cached['summary'];
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugins = get_plugins();
		$active = get_option( 'active_plugins', array() );
		$updates = get_site_transient( 'update_plugins' );
		$summary = array(
			'plugins_total' => count( $plugins ),
			'plugins_active' => count( $active ),
			'pending_plugin_updates' => is_object( $updates ) && ! empty( $updates->response ) && is_array( $updates->response ) ? count( $updates->response ) : 0,
		);
		update_option( self::INVENTORY_CACHE, array( 'last_run' => time(), 'summary' => $summary ), false );
		return $summary;
	}

	public static function scan_malware_path( $root, $max_files = 7000, $max_findings = 500 ) {
		$signatures = self::malware_signatures();
		$findings = array();
		$scanned = 0;

		try {
			$iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
			foreach ( $iterator as $file ) {
				if ( $scanned >= $max_files || count( $findings ) >= $max_findings ) {
					break;
				}
				if ( ! $file->isFile() ) {
					continue;
				}

				$path = $file->getPathname();
				$rel = ltrim( str_replace( $root, '', $path ), DIRECTORY_SEPARATOR );
				$rel = str_replace( '\\', '/', $rel );
				if ( preg_match( '~(^|/)(cache|wpsmm-backups|wpsma-backups|node_modules|vendor/composer|\.git|\.svn)(/|$)~i', $rel ) ) {
					continue;
				}
				if ( ! preg_match( '~(\.php|\.phtml|\.php[0-9]?|\.js|\.htaccess)$~i', $path ) || $file->getSize() > 2 * 1024 * 1024 ) {
					continue;
				}

				$scanned++;
				$content = @file_get_contents( $path, false, null, 0, 2000000 );
				if ( false === $content || '' === $content ) {
					continue;
				}

				foreach ( $signatures as $name => $rule ) {
					if ( ! preg_match_all( $rule['regex'], $content, $matches, PREG_OFFSET_CAPTURE ) ) {
						continue;
					}
					$limit = 5;
					foreach ( $matches[0] as $match ) {
						if ( $limit <= 0 || count( $findings ) >= $max_findings ) {
							break 2;
						}
						$line = self::malware_line_number( $content, (int) $match[1] );
						$findings[] = array(
							'file' => $rel,
							'line' => $line,
							'signature' => $name,
							'risk' => $rule['risk'],
							'title' => $rule['title'],
							'description' => $rule['description'],
							'match' => self::malware_shorten( (string) $match[0], 160 ),
							'code' => self::malware_shorten( self::malware_line_excerpt( $content, $line ), 260 ),
						);
						$limit--;
					}
				}
			}
		} catch ( Throwable $e ) {
			return array( 'scanned' => $scanned, 'findings' => $findings, 'error' => $e->getMessage() );
		}

		return array( 'scanned' => $scanned, 'findings' => $findings );
	}

	public static function malware_signatures() {
		$host = preg_quote( parse_url( home_url(), PHP_URL_HOST ) ?: '', '/' );
		return array(
			'eval_base64' => array( 'title' => 'Eval + base64 payload', 'description' => 'Common encoded loader/backdoor pattern.', 'risk' => 'critical', 'regex' => '/eval\s*\(\s*base64_decode\s*\(/i' ),
			'gzinflate_payload' => array( 'title' => 'Gzinflate payload', 'description' => 'Compressed or encoded payload often used to hide malicious code.', 'risk' => 'high', 'regex' => '/gzinflate\s*\(\s*base64_decode\s*\(/i' ),
			'assert_request' => array( 'title' => 'Assert from request', 'description' => 'Potential execution of GET/POST/REQUEST data.', 'risk' => 'critical', 'regex' => '/assert\s*\(\s*\$_(POST|REQUEST|GET)/i' ),
			'dangerous_exec_request' => array( 'title' => 'Command execution from request', 'description' => 'Potential system command execution from user input.', 'risk' => 'critical', 'regex' => '/(shell_exec|exec|passthru|system|proc_open|popen)\s*\(\s*\$_(POST|REQUEST|GET)/i' ),
			'preg_replace_eval' => array( 'title' => 'Preg replace /e', 'description' => 'Legacy code execution pattern that is often abused.', 'risk' => 'high', 'regex' => '/preg_replace\s*\(.{0,160}\/e[\'\"]/is' ),
			'variable_function_request' => array( 'title' => 'Variable function from request', 'description' => 'Dynamic function call controlled by request data.', 'risk' => 'high', 'regex' => '/\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*\$_(GET|POST|REQUEST)\s*\[[^\]]+\].{0,120}\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(/is' ),
			'file_write_request' => array( 'title' => 'File write from request', 'description' => 'Request data may be written to disk.', 'risk' => 'high', 'regex' => '/(file_put_contents|fwrite)\s*\(.{0,220}\$_(POST|REQUEST|GET)/is' ),
			'hidden_iframe' => array( 'title' => 'Hidden iframe', 'description' => 'Hidden iframe pattern often seen in injected malware or SEO spam.', 'risk' => 'medium', 'regex' => '/<iframe[^>]+style=[\'\"][^\'\"]*(display\s*:\s*none|visibility\s*:\s*hidden)/i' ),
			'seo_spam_keywords' => array( 'title' => 'SEO spam keyword', 'description' => 'Casino/pharma/loan/adult spam keyword detected.', 'risk' => 'medium', 'regex' => '/(casino|betting|viagra|loan payday|porn|adult dating)/i' ),
			'suspicious_htaccess_redirect' => array( 'title' => '.htaccess external redirect', 'description' => 'Rewrite or redirect to an external domain.', 'risk' => 'high', 'regex' => '/RewriteRule\s+\^.*https?:\/\/(?!' . $host . ')/i' ),
		);
	}

	private static function malware_line_number( $content, $offset ) {
		return substr_count( substr( $content, 0, max( 0, $offset ) ), "\n" ) + 1;
	}

	private static function malware_line_excerpt( $content, $line ) {
		$lines = preg_split( '/\R/', $content );
		$index = max( 0, $line - 1 );
		return isset( $lines[ $index ] ) ? trim( (string) $lines[ $index ] ) : '';
	}

	private static function malware_shorten( $value, $max ) {
		$value = preg_replace( '/\s+/', ' ', trim( $value ) );
		if ( function_exists( 'mb_strlen' ) && mb_strlen( $value ) > $max ) {
			return mb_substr( $value, 0, $max - 3 ) . '...';
		}
		return strlen( $value ) > $max ? substr( $value, 0, $max - 3 ) . '...' : $value;
	}
}
