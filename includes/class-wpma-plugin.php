<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPMA_Plugin {
	const OPTION          = 'wpma_settings';
	const INVENTORY_CACHE = 'wpma_inventory_cache';
	const INVENTORY_INTERVAL = 6 * HOUR_IN_SECONDS;

	public static function init() {
		self::cleanup_removed_feature_settings();
		self::ensure_agent_secret();
		add_action( 'admin_init', array( __CLASS__, 'maybe_upgrade' ) );
		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue_admin_assets' ) );
		add_action( 'admin_init', array( __CLASS__, 'handle_settings_save' ) );
		add_action( 'admin_notices', array( __CLASS__, 'show_notice' ) );
		add_filter( 'all_plugins', array( __CLASS__, 'hide_from_plugins_list' ) );
		add_filter( 'user_has_cap', array( __CLASS__, 'grant_delegated_capabilities' ), 10, 4 );
		add_filter( 'repu_allow_editor_capability', array( __CLASS__, 'allow_delegated_protected_capability' ), 10, 3 );
		add_filter( 'map_meta_cap', array( __CLASS__, 'protect_sso_user_from_deletion' ), 20, 4 );
		add_action( 'before_delete_user', array( __CLASS__, 'prevent_sso_user_deletion' ), 1 );
		add_action( 'wpmu_delete_user', array( __CLASS__, 'prevent_sso_user_deletion' ), 1 );
		add_filter( 'user_row_actions', array( __CLASS__, 'hide_sso_user_delete_action' ), 20, 2 );
		add_action( 'rest_api_init', array( __CLASS__, 'register_rest_routes' ) );
	}

	public static function defaults() {
		return array(
			'hide_agent'      => 0,
			'access_log_path' => '',
			'log_lines'       => 200,
			'agent_secret'    => '',
			'enable_sso'      => 0,
			'sso_user_id'     => 0,
			'authorized_users' => array(),
		);
	}

	public static function settings() {
		$settings = get_option( self::OPTION, array() );
		$settings = wp_parse_args( is_array( $settings ) ? $settings : array(), self::defaults() );
		$settings['hide_agent'] = ! empty( $settings['hide_agent'] ) ? 1 : 0;
		$settings['access_log_path'] = isset( $settings['access_log_path'] ) ? (string) $settings['access_log_path'] : '';
		$settings['log_lines'] = min( 1000, max( 20, absint( $settings['log_lines'] ) ) );
		$settings['agent_secret'] = isset( $settings['agent_secret'] ) ? (string) $settings['agent_secret'] : '';
		$settings['enable_sso'] = ! empty( $settings['enable_sso'] ) ? 1 : 0;
		$settings['sso_user_id'] = absint( $settings['sso_user_id'] );
		$settings['authorized_users'] = self::sanitize_authorized_users( $settings['authorized_users'] );
		return $settings;
	}

	private static function cleanup_removed_feature_settings() {
		$settings = get_option( self::OPTION, array() );
		if ( is_array( $settings ) && array_key_exists( 'secret', $settings ) ) {
			unset( $settings['secret'] );
			update_option( self::OPTION, $settings, false );
		}
	}

	public static function activate() {
		self::ensure_agent_secret();
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
				'hide_agent'      => ! empty( $settings['hide_agent'] ) ? 1 : 0,
				'access_log_path' => isset( $settings['access_log_path'] ) ? self::sanitize_log_path( $settings['access_log_path'] ) : '',
				'log_lines'       => isset( $settings['log_lines'] ) ? min( 1000, max( 20, absint( $settings['log_lines'] ) ) ) : 200,
				'agent_secret'    => isset( $settings['agent_secret'] ) ? (string) $settings['agent_secret'] : '',
				'enable_sso'      => ! empty( $settings['enable_sso'] ) ? 1 : 0,
				'sso_user_id'     => isset( $settings['sso_user_id'] ) ? absint( $settings['sso_user_id'] ) : 0,
				'authorized_users' => isset( $settings['authorized_users'] ) ? self::sanitize_authorized_users( $settings['authorized_users'] ) : array(),
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
			'/sso-ticket',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'rest_create_sso_ticket' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			'wpma/v1',
			'/inventory',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'rest_inventory' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			'wpma/v1',
			'/quick-login',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'rest_quick_login' ),
				'permission_callback' => '__return_true',
			)
		);

	}

	public static function rest_status() {
		return rest_ensure_response(
			array(
				'success'        => true,
				'agent'          => 'wp-site-monitor-agent',
			)
		);
	}

	public static function rest_create_sso_ticket( WP_REST_Request $request ) {
		if ( ! self::sso_transport_allowed() ) {
			return new WP_Error( 'wpma_sso_https_required', 'Đăng nhập nhanh yêu cầu website con sử dụng HTTPS.', array( 'status' => 403 ) );
		}

		$verified = self::verify_manager_signature( $request );
		if ( is_wp_error( $verified ) ) {
			return $verified;
		}
		$rate_key = 'wpma_sso_issue_rate_' . md5( self::request_ip() );
		$issued   = (int) get_transient( $rate_key );
		if ( $issued >= 20 ) {
			return new WP_Error( 'wpma_sso_issue_rate_limit', 'Có quá nhiều ticket đăng nhập được yêu cầu. Vui lòng thử lại sau.', array( 'status' => 429 ) );
		}
		set_transient( $rate_key, $issued + 1, 5 * MINUTE_IN_SECONDS );
		$username = sanitize_user( (string) $request->get_param( 'username' ) );
		if ( '' === $username ) {
			return new WP_Error( 'wpma_sso_missing_username', 'Thiếu tài khoản quản trị.', array( 'status' => 400 ) );
		}
		$user = get_user_by( 'login', $username );
		if ( ! $user && is_email( $username ) ) {
			$user = get_user_by( 'email', $username );
		}
		$settings = self::settings();
		if ( empty( $settings['enable_sso'] ) || ! $user || (int) $user->ID !== (int) $settings['sso_user_id'] || ! user_can( $user, 'manage_options' ) ) {
			return new WP_Error( 'wpma_sso_forbidden', 'Tài khoản không có quyền quản trị website.', array( 'status' => 403 ) );
		}

		$ticket = bin2hex( random_bytes( 32 ) );
		set_transient( 'wpma_sso_' . hash( 'sha256', $ticket ), array( 'user_id' => (int) $user->ID ), MINUTE_IN_SECONDS );

		return rest_ensure_response(
			array(
				'success'   => true,
				'login_url' => rest_url( 'wpma/v1/quick-login' ),
				'ticket'    => $ticket,
			)
		);
	}

	public static function rest_inventory( WP_REST_Request $request ) {
		if ( ! self::sso_transport_allowed() ) {
			return new WP_Error( 'wpma_inventory_https_required', 'Inventory yêu cầu website con sử dụng HTTPS.', array( 'status' => 403 ) );
		}

		$verified = self::verify_manager_signature( $request );
		if ( is_wp_error( $verified ) ) {
			return $verified;
		}

		$refresh   = (bool) $request->get_param( 'refresh' ) && ! get_transient( 'wpma_inventory_refresh_lock' );
		$inventory = $refresh ? false : get_transient( self::INVENTORY_CACHE );
		if ( ! is_array( $inventory ) ) {
			$inventory = self::collect_inventory();
			set_transient( self::INVENTORY_CACHE, $inventory, self::INVENTORY_INTERVAL );
			set_transient( 'wpma_inventory_refresh_lock', 1, 5 * MINUTE_IN_SECONDS );
		}

		return rest_ensure_response( array( 'success' => true, 'inventory' => $inventory ) );
	}

	public static function rest_quick_login( WP_REST_Request $request ) {
		$ticket = sanitize_text_field( (string) $request->get_param( 'ticket' ) );
		if ( ! preg_match( '/^[a-f0-9]{64}$/', $ticket ) ) {
			wp_die( 'Ticket đăng nhập không hợp lệ.', '', array( 'response' => 403 ) );
		}

		$key  = 'wpma_sso_' . hash( 'sha256', $ticket );
		$data = get_transient( $key );
		delete_transient( $key );
		$user = is_array( $data ) && ! empty( $data['user_id'] ) ? get_user_by( 'id', (int) $data['user_id'] ) : false;
		if ( ! $user || ! user_can( $user, 'manage_options' ) ) {
			wp_die( 'Ticket đăng nhập đã hết hạn hoặc đã được sử dụng.', '', array( 'response' => 403 ) );
		}

		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, true, is_ssl() );
		do_action( 'wp_login', $user->user_login, $user );
		wp_safe_redirect( admin_url() );
		exit;
	}

	private static function sso_transport_allowed() {
		return 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME ) || ( defined( 'WPMA_ALLOW_INSECURE_SSO' ) && WPMA_ALLOW_INSECURE_SSO );
	}

	private static function request_ip() {
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : 'unknown';
	}

	private static function verify_manager_signature( WP_REST_Request $request ) {
		$rate_key = 'wpma_signature_rate_' . md5( self::request_ip() );
		$attempts = (int) get_transient( $rate_key );
		if ( $attempts >= 10 ) {
			return new WP_Error( 'wpma_signature_rate_limit', 'Có quá nhiều yêu cầu không hợp lệ. Vui lòng thử lại sau.', array( 'status' => 429 ) );
		}
		if ( strlen( $request->get_body() ) > 4096 ) {
			return new WP_Error( 'wpma_request_too_large', 'Dữ liệu yêu cầu vượt quá giới hạn.', array( 'status' => 413 ) );
		}
		$timestamp = (string) $request->get_header( 'x-wpma-timestamp' );
		$nonce     = strtolower( (string) $request->get_header( 'x-wpma-nonce' ) );
		$signature = strtolower( (string) $request->get_header( 'x-wpma-signature' ) );
		if ( ! ctype_digit( $timestamp ) || abs( time() - (int) $timestamp ) > 120 || ! preg_match( '/^[a-f0-9]{32}$/', $nonce ) || ! preg_match( '/^[a-f0-9]{64}$/', $signature ) ) {
			set_transient( $rate_key, $attempts + 1, 5 * MINUTE_IN_SECONDS );
			return new WP_Error( 'wpma_signature_invalid', 'Chữ ký yêu cầu không hợp lệ.', array( 'status' => 403 ) );
		}
		$nonce_key = 'wpma_nonce_' . hash( 'sha256', $nonce );
		if ( get_transient( $nonce_key ) ) {
			set_transient( $rate_key, $attempts + 1, 5 * MINUTE_IN_SECONDS );
			return new WP_Error( 'wpma_signature_replay', 'Yêu cầu đã được sử dụng.', array( 'status' => 403 ) );
		}
		$settings  = self::settings();
		$canonical = $timestamp . "\n" . $nonce . "\n" . $request->get_route() . "\n" . hash( 'sha256', $request->get_body() );
		$expected  = hash_hmac( 'sha256', $canonical, (string) $settings['agent_secret'] );
		if ( ! hash_equals( $expected, $signature ) ) {
			set_transient( $rate_key, $attempts + 1, 5 * MINUTE_IN_SECONDS );
			return new WP_Error( 'wpma_signature_invalid', 'Chữ ký yêu cầu không hợp lệ.', array( 'status' => 403 ) );
		}
		set_transient( $nonce_key, 1, 5 * MINUTE_IN_SECONDS );
		delete_transient( $rate_key );
		return true;
	}

	private static function ensure_agent_secret() {
		$settings = get_option( self::OPTION, array() );
		$settings = is_array( $settings ) ? $settings : array();
		if ( empty( $settings['agent_secret'] ) || ! preg_match( '/^[a-f0-9]{64}$/', (string) $settings['agent_secret'] ) ) {
			$settings['agent_secret'] = bin2hex( random_bytes( 32 ) );
			update_option( self::OPTION, $settings, false );
		}
	}

	private static function collect_inventory() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/update.php';

		wp_update_plugins();
		wp_update_themes();
		$plugin_updates = get_site_transient( 'update_plugins' );
		$theme_updates  = get_site_transient( 'update_themes' );
		$active_plugins = (array) get_option( 'active_plugins', array() );
		$network_active = is_multisite() ? array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) : array();
		$plugins        = array();
		foreach ( get_plugins() as $file => $plugin ) {
			$update    = isset( $plugin_updates->response[ $file ] ) ? $plugin_updates->response[ $file ] : null;
			$plugins[] = array(
				'file'             => $file,
				'name'             => isset( $plugin['Name'] ) ? $plugin['Name'] : $file,
				'version'          => isset( $plugin['Version'] ) ? $plugin['Version'] : '',
				'active'           => in_array( $file, $active_plugins, true ) || in_array( $file, $network_active, true ),
				'update_available' => ! empty( $update ),
				'new_version'      => $update && isset( $update->new_version ) ? $update->new_version : '',
			);
		}

		$themes = array();
		foreach ( wp_get_themes() as $stylesheet => $theme ) {
			$update   = isset( $theme_updates->response[ $stylesheet ] ) ? $theme_updates->response[ $stylesheet ] : null;
			$themes[] = array(
				'stylesheet'       => $stylesheet,
				'name'             => $theme->get( 'Name' ),
				'version'          => $theme->get( 'Version' ),
				'active'           => get_stylesheet() === $stylesheet,
				'update_available' => ! empty( $update ),
				'new_version'      => $update && isset( $update['new_version'] ) ? $update['new_version'] : '',
			);
		}

		return array(
			'generated_at' => current_time( 'mysql' ),
			'wordpress'    => get_bloginfo( 'version' ),
			'php'          => PHP_VERSION,
			'database'     => $wpdb->db_version(),
			'server'       => isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : '',
			'plugins'      => $plugins,
			'themes'       => $themes,
		);
	}

	public static function is_hidden() {
		if ( defined( 'WPMA_FORCE_VISIBLE' ) && WPMA_FORCE_VISIBLE ) {
			return false;
		}
		return ! empty( self::settings()['hide_agent'] );
	}

	private static function sanitize_authorized_users( $users ) {
		if ( ! is_array( $users ) ) {
			return array();
		}

		$allowed_permissions = array( 'access_agent', 'view_logs', 'manage_settings', 'manage_plugins', 'install_plugins', 'manage_themes', 'edit_files' );
		$authorized_users    = array();
		foreach ( $users as $user_id => $permissions ) {
			$user_id = absint( $user_id );
			if ( ! $user_id || ! get_user_by( 'id', $user_id ) || ! is_array( $permissions ) ) {
				continue;
			}
			$authorized_users[ $user_id ] = array();
			$has_permission                = false;
			foreach ( $allowed_permissions as $permission ) {
				$authorized_users[ $user_id ][ $permission ] = ! empty( $permissions[ $permission ] ) ? 1 : 0;
				$has_permission = $has_permission || ! empty( $authorized_users[ $user_id ][ $permission ] );
			}
			if ( ! $has_permission ) {
				unset( $authorized_users[ $user_id ] );
			}
		}
		return $authorized_users;
	}

	private static function current_user_permission( $permission ) {
		$settings         = self::settings();
		$authorized_users = $settings['authorized_users'];
		$user_id          = get_current_user_id();
		if ( empty( $authorized_users ) ) {
			return current_user_can( 'manage_options' );
		}
		return ! empty( $authorized_users[ $user_id ]['access_agent'] ) && ! empty( $authorized_users[ $user_id ][ $permission ] );
	}

	private static function current_user_can_access_agent() {
		$settings         = self::settings();
		$authorized_users = $settings['authorized_users'];
		if ( empty( $authorized_users ) ) {
			return current_user_can( 'manage_options' );
		}
		return ! empty( $authorized_users[ get_current_user_id() ]['access_agent'] );
	}

	private static function current_user_can_manage_settings() {
		return self::current_user_permission( 'manage_settings' );
	}

	private static function current_user_can_view_logs() {
		return self::current_user_permission( 'view_logs' );
	}

	public static function grant_delegated_capabilities( $allcaps, $caps, $args, $user ) {
		$settings         = self::settings();
		$authorized_users = $settings['authorized_users'];
		$user_id          = isset( $user->ID ) ? absint( $user->ID ) : 0;
		if ( ! $user_id || empty( $authorized_users[ $user_id ] ) ) {
			return $allcaps;
		}

		$permissions = $authorized_users[ $user_id ];
		if ( ! empty( $permissions['manage_plugins'] ) ) {
			foreach ( array( 'activate_plugins', 'update_plugins', 'delete_plugins' ) as $capability ) {
				$allcaps[ $capability ] = true;
			}
		}
		if ( ! empty( $permissions['install_plugins'] ) ) {
			$allcaps['install_plugins'] = true;
			$allcaps['upload_plugins']  = true;
		}
		if ( ! empty( $permissions['manage_themes'] ) ) {
			foreach ( array( 'switch_themes', 'edit_theme_options', 'update_themes', 'delete_themes' ) as $capability ) {
				$allcaps[ $capability ] = true;
			}
		}
		if ( ! empty( $permissions['edit_files'] ) ) {
			$allcaps['edit_plugins'] = true;
			$allcaps['edit_themes']  = true;
		}
		return $allcaps;
	}

	public static function allow_delegated_protected_capability( $allowed, $capability, $user_id ) {
		if ( $allowed ) {
			return true;
		}

		$settings         = self::settings();
		$authorized_users = $settings['authorized_users'];
		$permissions      = isset( $authorized_users[ absint( $user_id ) ] ) ? $authorized_users[ absint( $user_id ) ] : array();
		$capability_map   = array(
			'activate_plugins' => 'manage_plugins',
			'update_plugins'   => 'manage_plugins',
			'delete_plugins'   => 'manage_plugins',
			'install_plugins'  => 'install_plugins',
			'upload_plugins'   => 'install_plugins',
			'switch_themes'    => 'manage_themes',
			'edit_theme_options' => 'manage_themes',
			'update_themes'    => 'manage_themes',
			'delete_themes'    => 'manage_themes',
			'edit_plugins'     => 'edit_files',
			'edit_themes'      => 'edit_files',
			'edit_files'       => 'edit_files',
		);

		return isset( $capability_map[ $capability ] ) && ! empty( $permissions[ $capability_map[ $capability ] ] );
	}

	private static function is_protected_sso_user( $user_id ) {
		$settings = self::settings();
		return ! empty( $settings['enable_sso'] ) && ! empty( $settings['sso_user_id'] ) && (int) $settings['sso_user_id'] === absint( $user_id );
	}

	public static function protect_sso_user_from_deletion( $caps, $capability, $user_id, $args ) {
		if ( in_array( $capability, array( 'delete_user', 'delete_users' ), true ) && ! empty( $args[0] ) && self::is_protected_sso_user( $args[0] ) ) {
			return array( 'do_not_allow' );
		}
		return $caps;
	}

	public static function prevent_sso_user_deletion( $user_id ) {
		if ( self::is_protected_sso_user( $user_id ) ) {
			wp_die( esc_html__( 'Không thể xóa tài khoản đang được chọn cho Quick login SSO. Hãy tắt SSO hoặc chọn tài khoản khác trước.', 'wp-site-monitor-agent' ), '', array( 'response' => 403 ) );
		}
	}

	public static function hide_sso_user_delete_action( $actions, $user ) {
		if ( isset( $user->ID ) && self::is_protected_sso_user( $user->ID ) ) {
			unset( $actions['delete'] );
		}
		return $actions;
	}

	public static function admin_menu() {
		if ( self::is_hidden() || ! self::current_user_can_access_agent() ) {
			return;
		}

		add_menu_page(
			__( 'WP Site Monitor Agent', 'wp-site-monitor-agent' ),
			__( 'WP Site Monitor Agent', 'wp-site-monitor-agent' ),
			'read',
			'wp-site-monitor-agent',
			array( __CLASS__, 'render_settings_page' ),
			'dashicons-shield-alt',
			59
		);
	}

	public static function enqueue_admin_assets( $hook ) {
		if ( 'toplevel_page_wp-site-monitor-agent' !== $hook ) {
			return;
		}

		wp_enqueue_style( 'wpma-admin', plugins_url( 'assets/css/admin.css', WPMA_PLUGIN_FILE ), array(), WPMA_VERSION );
	}

	public static function hide_from_plugins_list( $plugins ) {
		if ( self::is_hidden() && isset( $plugins[ plugin_basename( WPMA_PLUGIN_FILE ) ] ) ) {
			unset( $plugins[ plugin_basename( WPMA_PLUGIN_FILE ) ] );
		}
		return $plugins;
	}

	public static function handle_settings_save() {
		if ( empty( $_POST['wpma_save_settings'] ) ) {
			return;
		}

		if ( ! self::current_user_can_manage_settings() ) {
			wp_die( esc_html__( 'Bạn không có quyền chỉnh sửa cài đặt WP Site Monitor Agent.', 'wp-site-monitor-agent' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( 'wpma_save_settings', 'wpma_nonce' );
		$current  = self::settings();
		$settings = array(
			'hide_agent'      => ! empty( $_POST['hide_agent'] ) ? 1 : 0,
			'access_log_path' => isset( $_POST['access_log_path'] ) ? self::sanitize_log_path( wp_unslash( $_POST['access_log_path'] ) ) : '',
			'log_lines'       => isset( $_POST['log_lines'] ) ? min( 1000, max( 20, absint( $_POST['log_lines'] ) ) ) : 200,
			'agent_secret'    => ! empty( $current['agent_secret'] ) ? (string) $current['agent_secret'] : bin2hex( random_bytes( 32 ) ),
			'enable_sso'      => ! empty( $_POST['enable_sso'] ) ? 1 : 0,
			'sso_user_id'     => isset( $_POST['sso_user_id'] ) ? absint( $_POST['sso_user_id'] ) : 0,
			'authorized_users' => $current['authorized_users'],
		);
		if ( ! empty( $settings['enable_sso'] ) ) {
			$sso_user = $settings['sso_user_id'] ? get_user_by( 'id', $settings['sso_user_id'] ) : false;
			if ( ! $sso_user || ! user_can( $sso_user, 'manage_options' ) ) {
				add_settings_error( 'wpma_messages', 'wpma_sso_admin_required', __( 'Quick login SSO yêu cầu chọn một tài khoản quản trị viên hợp lệ.', 'wp-site-monitor-agent' ), 'error' );
				return;
			}
		}
		if ( current_user_can( 'manage_options' ) ) {
			$authorized_users = isset( $_POST['authorized_users'] ) ? self::sanitize_authorized_users( wp_unslash( $_POST['authorized_users'] ) ) : array();
			if ( empty( $authorized_users ) ) {
				add_settings_error( 'wpma_messages', 'wpma_access_required', __( 'Phải chỉ định ít nhất một tài khoản được phép truy cập Agent.', 'wp-site-monitor-agent' ), 'error' );
				return;
			}
			$has_admin_manager = false;
			foreach ( $authorized_users as $user_id => $permissions ) {
				$user = get_user_by( 'id', $user_id );
				if ( $user && user_can( $user, 'manage_options' ) && ! empty( $permissions['access_agent'] ) && ! empty( $permissions['manage_settings'] ) ) {
					$has_admin_manager = true;
					break;
				}
			}
			if ( ! $has_admin_manager ) {
				add_settings_error( 'wpma_messages', 'wpma_admin_manager_required', __( 'Phải giữ lại ít nhất một quản trị viên có quyền sửa cài đặt Agent để tránh mất quyền truy cập cấu hình.', 'wp-site-monitor-agent' ), 'error' );
				return;
			}
			$settings['authorized_users'] = $authorized_users;
		}
		if ( ! empty( $_POST['regenerate_agent_secret'] ) ) {
			$settings['agent_secret'] = bin2hex( random_bytes( 32 ) );
		}

		update_option( self::OPTION, $settings, false );
		if ( class_exists( 'WPMA_GitHub_Updater' ) ) {
			WPMA_GitHub_Updater::clear_cache();
		}
		add_settings_error( 'wpma_messages', 'wpma_saved', __( 'Agent settings saved.', 'wp-site-monitor-agent' ), 'updated' );
	}

	public static function render_settings_page() {
		if ( ! self::current_user_can_access_agent() ) {
			wp_die( esc_html__( 'Bạn không có quyền truy cập WP Site Monitor Agent.', 'wp-site-monitor-agent' ), '', array( 'response' => 403 ) );
		}

		$settings = self::settings();
		$can_manage_settings = self::current_user_can_manage_settings();
		?>
		<div class="wrap wpma-wrap">
			<header class="wpma-page-header">
				<div class="wpma-page-icon"><span class="dashicons dashicons-shield-alt"></span></div>
				<div><h1><?php esc_html_e( 'WP Site Monitor Agent', 'wp-site-monitor-agent' ); ?></h1>
				<p><?php esc_html_e( 'Kết nối website này với WP Site Monitor Manager, cấu hình đăng nhập nhanh và kiểm tra access log.', 'wp-site-monitor-agent' ); ?></p></div>
			</header>
			<?php settings_errors( 'wpma_messages' ); ?>
			<?php if ( $can_manage_settings ) : ?>
			<form method="post" action="" class="wpma-settings-form">
				<?php wp_nonce_field( 'wpma_save_settings', 'wpma_nonce' ); ?>
				<div class="wpma-card">
					<div class="wpma-card-heading"><h2><?php esc_html_e( 'Cấu hình Agent', 'wp-site-monitor-agent' ); ?></h2><p><?php esc_html_e( 'Thiết lập kết nối với Manager và nguồn dữ liệu nhật ký máy chủ.', 'wp-site-monitor-agent' ); ?></p></div>
				<table class="form-table wpma-form-table" role="presentation">
					<tr>
						<th><?php esc_html_e( 'Agent endpoint', 'wp-site-monitor-agent' ); ?></th>
						<td>
							<code><?php echo esc_html( rest_url( 'wpma/v1/status' ) ); ?></code>
							<p class="description"><?php esc_html_e( 'Health status endpoint for WP Site Monitor Manager.', 'wp-site-monitor-agent' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><label for="agent_secret"><?php esc_html_e( 'Manager connection key', 'wp-site-monitor-agent' ); ?></label></th>
						<td>
							<input id="agent_secret" type="text" class="large-text code" value="<?php echo esc_attr( $settings['agent_secret'] ); ?>" readonly>
							<p class="description"><?php esc_html_e( 'Copy this key into the website configuration in WP Site Monitor Manager. Rotate it if you suspect exposure.', 'wp-site-monitor-agent' ); ?></p>
							<label><input type="checkbox" name="regenerate_agent_secret" value="1"> <?php esc_html_e( 'Generate a new key when saving settings', 'wp-site-monitor-agent' ); ?></label>
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Quick login SSO', 'wp-site-monitor-agent' ); ?></th>
						<td>
							<label><input type="checkbox" name="enable_sso" value="1" <?php checked( $settings['enable_sso'] ); ?>> <?php esc_html_e( 'Allow signed one-click login requests from the manager', 'wp-site-monitor-agent' ); ?></label>
							<p><select name="sso_user_id"><option value="0"><?php esc_html_e( 'Select an administrator', 'wp-site-monitor-agent' ); ?></option><?php foreach ( get_users( array( 'role' => 'administrator' ) ) as $admin_user ) : ?><option value="<?php echo esc_attr( $admin_user->ID ); ?>" <?php selected( $settings['sso_user_id'], $admin_user->ID ); ?>><?php echo esc_html( $admin_user->user_login ); ?></option><?php endforeach; ?></select></p>
							<p class="description"><?php esc_html_e( 'Only the selected administrator can receive a one-click login ticket.', 'wp-site-monitor-agent' ); ?></p>
							<p class="description"><?php esc_html_e( 'Khi SSO đang bật, tài khoản được chọn không thể bị xóa. Hãy chọn tài khoản khác hoặc tắt SSO trước khi xóa.', 'wp-site-monitor-agent' ); ?></p>
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
					<?php if ( current_user_can( 'manage_options' ) ) : ?>
					<tr>
						<th><?php esc_html_e( 'Phân quyền tài khoản', 'wp-site-monitor-agent' ); ?></th>
						<td>
							<p class="description"><?php esc_html_e( 'Mỗi quyền hoạt động độc lập. Chỉ bật Truy cập Agent nếu tài khoản cần mở trang này; các quyền quản lý plugin vẫn có thể cấp riêng.', 'wp-site-monitor-agent' ); ?></p>
							<div class="wpma-table-scroll"><table class="widefat striped wpma-permissions-table">
								<thead><tr><th><?php esc_html_e( 'Tài khoản', 'wp-site-monitor-agent' ); ?></th><th><?php esc_html_e( 'Truy cập Agent', 'wp-site-monitor-agent' ); ?></th><th><?php esc_html_e( 'Xem file log', 'wp-site-monitor-agent' ); ?></th><th><?php esc_html_e( 'Sửa cài đặt Agent', 'wp-site-monitor-agent' ); ?></th><th><?php esc_html_e( 'Quản lý plugin', 'wp-site-monitor-agent' ); ?></th><th><?php esc_html_e( 'Cài plugin', 'wp-site-monitor-agent' ); ?></th><th><?php esc_html_e( 'Quản lý giao diện', 'wp-site-monitor-agent' ); ?></th><th><?php esc_html_e( 'Sửa file plugin/theme', 'wp-site-monitor-agent' ); ?></th></tr></thead>
								<tbody>
								<?php foreach ( get_users( array( 'orderby' => 'display_name' ) ) as $account ) : $permissions = isset( $settings['authorized_users'][ $account->ID ] ) ? $settings['authorized_users'][ $account->ID ] : array(); ?>
									<tr>
										<td><strong><?php echo esc_html( $account->display_name ); ?></strong><br><code><?php echo esc_html( $account->user_login ); ?></code></td>
										<td><input type="checkbox" name="authorized_users[<?php echo esc_attr( $account->ID ); ?>][access_agent]" value="1" <?php checked( ! empty( $permissions['access_agent'] ) ); ?>></td>
										<td><input type="checkbox" name="authorized_users[<?php echo esc_attr( $account->ID ); ?>][view_logs]" value="1" <?php checked( ! empty( $permissions['view_logs'] ) ); ?>></td>
										<td><input type="checkbox" name="authorized_users[<?php echo esc_attr( $account->ID ); ?>][manage_settings]" value="1" <?php checked( ! empty( $permissions['manage_settings'] ) ); ?>></td>
										<td><input type="checkbox" name="authorized_users[<?php echo esc_attr( $account->ID ); ?>][manage_plugins]" value="1" <?php checked( ! empty( $permissions['manage_plugins'] ) ); ?>></td>
										<td><input type="checkbox" name="authorized_users[<?php echo esc_attr( $account->ID ); ?>][install_plugins]" value="1" <?php checked( ! empty( $permissions['install_plugins'] ) ); ?>></td>
										<td><input type="checkbox" name="authorized_users[<?php echo esc_attr( $account->ID ); ?>][manage_themes]" value="1" <?php checked( ! empty( $permissions['manage_themes'] ) ); ?>></td>
										<td><input type="checkbox" name="authorized_users[<?php echo esc_attr( $account->ID ); ?>][edit_files]" value="1" <?php checked( ! empty( $permissions['edit_files'] ) ); ?>></td>
									</tr>
								<?php endforeach; ?>
								</tbody>
							</table></div>
							<p class="description"><?php esc_html_e( 'Cảnh báo: quyền sửa file plugin/theme có thể thay đổi mã nguồn đang chạy. Chỉ bật cho tài khoản tin cậy và sử dụng trong thời gian cần thiết.', 'wp-site-monitor-agent' ); ?></p>
						</td>
					</tr>
					<?php endif; ?>
				</table>
				</div>
				<div class="wpma-savebar"><?php submit_button( __( 'Lưu thay đổi', 'wp-site-monitor-agent' ), 'primary', 'wpma_save_settings', false ); ?></div>
			</form>
			<?php else : ?>
				<div class="notice notice-info inline"><p><?php esc_html_e( 'Tài khoản của bạn chỉ có quyền xem các khu vực được chỉ định. Liên hệ quản trị viên để thay đổi cấu hình Agent.', 'wp-site-monitor-agent' ); ?></p></div>
			<?php endif; ?>
			<?php if ( self::current_user_can_view_logs() ) : self::render_log_viewer( $settings ); endif; ?>
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
		<section class="wpma-card wpma-log-card">
		<div class="wpma-card-heading"><h2><?php esc_html_e( 'Access Log Viewer', 'wp-site-monitor-agent' ); ?></h2>
		<p><?php esc_html_e( 'Xem nhanh các dòng access log gần nhất mà không cần mở trang quản trị hosting.', 'wp-site-monitor-agent' ); ?></p></div>
		<form method="get" action="<?php echo esc_url( admin_url( 'admin.php' ) ); ?>" class="wpma-log-toolbar">
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
			<pre class="wpma-log-output"><?php echo esc_html( self::read_log_tail( $path, $lines ) ); ?></pre>
		<?php endif; ?>
		</section>
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

}
