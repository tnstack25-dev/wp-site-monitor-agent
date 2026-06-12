<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class WPMA_Access_Logger {
	const CLEANUP_HOOK = 'wpma_access_log_cleanup';
	const DIRECTORY_NAME = 'wpma-logs';
	const ERROR_TRANSIENT = 'wpma_access_log_error';

	private static $settings = array();
	private static $started_at = 0.0;

	public static function init( $settings ) {
		self::$settings = is_array( $settings ) ? $settings : array();
		add_action( self::CLEANUP_HOOK, array( __CLASS__, 'cleanup' ) );
		if ( empty( self::$settings['enable_access_log'] ) || in_array( PHP_SAPI, array( 'cli', 'phpdbg' ), true ) ) {
			return;
		}
		self::$started_at = isset( $_SERVER['REQUEST_TIME_FLOAT'] ) ? (float) $_SERVER['REQUEST_TIME_FLOAT'] : microtime( true );
		add_action( 'shutdown', array( __CLASS__, 'write' ), PHP_INT_MAX );
	}

	public static function schedule_cleanup() {
		if ( ! wp_next_scheduled( self::CLEANUP_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CLEANUP_HOOK );
		}
	}

	public static function log_pattern() {
		return trailingslashit( self::directory() ) . 'access-{Y-m-d}.log';
	}

	public static function view_file( $date ) {
		$date = preg_match( '/^\d{4}-\d{2}-\d{2}$/', (string) $date ) ? (string) $date : gmdate( 'Y-m-d' );
		$base = trailingslashit( self::directory() ) . 'access-' . $date;
		$files = glob( $base . '*.log' ) ?: array();
		if ( empty( $files ) ) {
			return $base . '.log';
		}
		natsort( $files );
		return (string) end( $files );
	}

	public static function write() {
		$directory = self::directory();
		if ( ! self::prepare_directory( $directory ) ) {
			self::report_error( 'Không thể tạo hoặc ghi vào thư mục access log: ' . $directory );
			return;
		}

		$line = wp_json_encode( self::entry(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		if ( ! is_string( $line ) ) {
			self::report_error( 'Không thể mã hóa dữ liệu access log.' );
			return;
		}

		$file = self::writable_file( $directory );
		$result = @file_put_contents( $file, $line . PHP_EOL, FILE_APPEND | LOCK_EX );
		if ( false === $result ) {
			self::report_error( 'Không thể ghi access log: ' . $file );
			return;
		}
	}

	public static function cleanup() {
		$settings = WPMA_Plugin::settings();
		$retention = min( 365, max( 1, absint( $settings['access_log_retention_days'] ) ) );
		$cutoff = time() - ( $retention * DAY_IN_SECONDS );
		foreach ( glob( trailingslashit( self::directory() ) . 'access-*.log' ) ?: array() as $file ) {
			$modified = filemtime( $file );
			if ( is_file( $file ) && false !== $modified && $modified < $cutoff ) {
				@unlink( $file );
			}
		}
	}

	private static function entry() {
		$status = http_response_code();
		$status = is_int( $status ) && $status >= 100 ? $status : 200;
		$last_error = error_get_last();
		$fatal_types = array( E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR );
		$fatal = is_array( $last_error ) && in_array( (int) $last_error['type'], $fatal_types, true );
		if ( $fatal && $status < 500 ) {
			$status = 500;
		}
		$user = wp_get_current_user();
		$entry = array(
			'time'           => gmdate( 'c' ),
			'request_id'     => self::request_id(),
			'ip'             => self::client_ip(),
			'method'         => self::method(),
			'path'           => self::path(),
			'status'         => $status,
			'fatal'          => $fatal,
			'duration_ms'    => round( max( 0, microtime( true ) - self::$started_at ) * 1000, 2 ),
			'peak_memory_mb' => round( memory_get_peak_usage( true ) / MB_IN_BYTES, 2 ),
			'user_id'        => $user->exists() ? (int) $user->ID : 0,
			'referer'        => self::referer(),
			'user_agent'     => self::header( 'HTTP_USER_AGENT', 512 ),
		);
		return apply_filters( 'wpma_access_log_entry', $entry );
	}

	private static function directory() {
		if ( defined( 'WPMA_ACCESS_LOG_DIR' ) && is_string( WPMA_ACCESS_LOG_DIR ) && '' !== trim( WPMA_ACCESS_LOG_DIR ) ) {
			return wp_normalize_path( untrailingslashit( WPMA_ACCESS_LOG_DIR ) );
		}
		$parent = dirname( wp_normalize_path( ABSPATH ) );
		if ( is_dir( $parent ) && is_writable( $parent ) ) {
			return trailingslashit( $parent ) . self::DIRECTORY_NAME;
		}
		return trailingslashit( wp_normalize_path( WP_CONTENT_DIR ) ) . self::DIRECTORY_NAME;
	}

	private static function prepare_directory( $directory ) {
		if ( ! is_dir( $directory ) && ! wp_mkdir_p( $directory ) ) {
			return false;
		}
		$files = array(
			'index.php'  => "<?php\nhttp_response_code( 403 );\nexit;\n",
			'.htaccess'  => "Require all denied\nDeny from all\n",
			'web.config' => '<?xml version="1.0" encoding="UTF-8"?><configuration><system.webServer><security><authorization><remove users="*" roles="" verbs=""/><add accessType="Deny" users="*"/></authorization></security></system.webServer></configuration>',
		);
		foreach ( $files as $name => $contents ) {
			$file = trailingslashit( $directory ) . $name;
			if ( ! file_exists( $file ) && false === @file_put_contents( $file, $contents, LOCK_EX ) ) {
				return false;
			}
		}
		return is_writable( $directory );
	}

	private static function writable_file( $directory ) {
		$base = trailingslashit( $directory ) . 'access-' . gmdate( 'Y-m-d' );
		$limit = min( 1024, max( 1, absint( self::$settings['access_log_max_file_mb'] ?? 50 ) ) ) * MB_IN_BYTES;
		for ( $part = 0; $part < 1000; $part++ ) {
			$file = $base . ( $part ? '-' . $part : '' ) . '.log';
			clearstatcache( true, $file );
			$size = is_file( $file ) ? filesize( $file ) : 0;
			if ( false === $size || $size < $limit ) {
				return $file;
			}
		}
		return $base . '-overflow.log';
	}

	private static function client_ip() {
		$remote = self::valid_ip( $_SERVER['REMOTE_ADDR'] ?? '' );
		$ip = $remote;
		$trusted = defined( 'WPMA_TRUSTED_PROXY_IPS' ) && is_array( WPMA_TRUSTED_PROXY_IPS ) ? WPMA_TRUSTED_PROXY_IPS : array();
		$trusted = apply_filters( 'wpma_trusted_proxy_ips', $trusted );
		$trusted = is_array( $trusted ) ? array_filter( array_map( array( __CLASS__, 'valid_ip' ), $trusted ) ) : array();
		if ( $remote && in_array( $remote, $trusted, true ) ) {
			$forwarded = explode( ',', (string) ( $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '' ) );
			foreach ( $forwarded as $candidate ) {
				$candidate = self::valid_ip( trim( $candidate ) );
				if ( $candidate ) {
					$ip = $candidate;
					break;
				}
			}
		}
		return ! empty( self::$settings['access_log_anonymize_ip'] ) ? self::anonymize_ip( $ip ) : $ip;
	}

	private static function anonymize_ip( $ip ) {
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$parts = explode( '.', $ip );
			$parts[3] = '0';
			return implode( '.', $parts );
		}
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$binary = inet_pton( $ip );
			return $binary ? inet_ntop( substr( $binary, 0, 6 ) . str_repeat( "\0", 10 ) ) : '';
		}
		return '';
	}

	private static function valid_ip( $ip ) {
		$ip = trim( (string) $ip );
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
	}

	private static function method() {
		$method = strtoupper( (string) ( $_SERVER['REQUEST_METHOD'] ?? 'GET' ) );
		return preg_match( '/^[A-Z]{1,16}$/', $method ) ? $method : 'UNKNOWN';
	}

	private static function path() {
		$path = wp_parse_url( (string) ( $_SERVER['REQUEST_URI'] ?? '/' ), PHP_URL_PATH );
		$path = is_string( $path ) && '' !== $path ? $path : '/';
		$path = substr( preg_replace( '/[\x00-\x1F\x7F]/', '', $path ), 0, 2048 );
		$path = (string) apply_filters( 'wpma_access_log_path', $path );
		return substr( preg_replace( '/[\x00-\x1F\x7F]/', '', $path ), 0, 2048 );
	}

	private static function referer() {
		$referer = self::header( 'HTTP_REFERER', 2048 );
		$scheme = wp_parse_url( $referer, PHP_URL_SCHEME );
		$host = wp_parse_url( $referer, PHP_URL_HOST );
		$path = wp_parse_url( $referer, PHP_URL_PATH );
		return is_string( $scheme ) && is_string( $host ) ? substr( strtolower( $scheme ) . '://' . strtolower( $host ) . ( is_string( $path ) ? $path : '/' ), 0, 1024 ) : '';
	}

	private static function header( $key, $limit ) {
		$value = preg_replace( '/[\x00-\x1F\x7F]/', '', (string) ( $_SERVER[ $key ] ?? '' ) );
		return substr( (string) $value, 0, $limit );
	}

	private static function request_id() {
		$provided = self::header( 'HTTP_X_REQUEST_ID', 128 );
		if ( preg_match( '/^[A-Za-z0-9._:-]{8,128}$/', $provided ) ) {
			return $provided;
		}
		try {
			return bin2hex( random_bytes( 8 ) );
		} catch ( Exception $exception ) {
			return substr( str_replace( '-', '', wp_generate_uuid4() ), 0, 16 );
		}
	}

	private static function report_error( $message ) {
		if ( false === get_transient( self::ERROR_TRANSIENT ) ) {
			set_transient( self::ERROR_TRANSIENT, array( 'time' => time(), 'message' => sanitize_text_field( $message ) ), HOUR_IN_SECONDS );
		}
	}
}
