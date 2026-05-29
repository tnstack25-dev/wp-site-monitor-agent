<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPMA_GitHub_Updater {
	const CACHE_KEY = 'wpma_github_update_release';
	const CACHE_TTL = 6 * HOUR_IN_SECONDS;

	public static function register() {
		add_filter( 'pre_set_site_transient_update_plugins', array( __CLASS__, 'check_for_updates' ) );
		add_filter( 'plugins_api', array( __CLASS__, 'plugin_info' ), 20, 3 );
		add_filter( 'upgrader_source_selection', array( __CLASS__, 'rename_source_directory' ), 10, 4 );
	}

	public static function check_for_updates( $transient ) {
		if ( ! is_object( $transient ) ) {
			return $transient;
		}

		$release = self::latest_release();
		if ( ! $release || empty( $release['version'] ) || version_compare( $release['version'], WPMA_VERSION, '<=' ) ) {
			return $transient;
		}

		$plugin = plugin_basename( WPMA_PLUGIN_FILE );
		$transient->response[ $plugin ] = (object) array(
			'id'           => $plugin,
			'slug'         => dirname( $plugin ),
			'plugin'       => $plugin,
			'new_version'  => $release['version'],
			'url'          => $release['html_url'] ?? self::repo_url(),
			'package'      => $release['package'] ?? '',
			'tested'       => get_bloginfo( 'version' ),
			'requires_php' => '7.4',
		);

		return $transient;
	}

	public static function plugin_info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || empty( $args->slug ) || dirname( plugin_basename( WPMA_PLUGIN_FILE ) ) !== $args->slug ) {
			return $result;
		}

		$release = self::latest_release( true );
		if ( ! $release ) {
			return $result;
		}

		return (object) array(
			'name'          => 'WP Site Monitor Agent',
			'slug'          => dirname( plugin_basename( WPMA_PLUGIN_FILE ) ),
			'version'       => $release['version'] ?? WPMA_VERSION,
			'author'        => '<a href="https://tnstack.com">TNStack</a>',
			'homepage'      => self::repo_url(),
			'requires'      => '5.8',
			'requires_php'  => '7.4',
			'tested'        => get_bloginfo( 'version' ),
			'download_link' => $release['package'] ?? '',
			'last_updated'  => $release['published_at'] ?? '',
			'sections'      => array(
				'description' => 'Child agent for WP Site Monitor Manager: signed health checks, remote malware scanning, and access log viewer.',
				'changelog'   => wp_kses_post( nl2br( (string) ( $release['body'] ?? 'No changelog provided.' ) ) ),
			),
		);
	}

	public static function rename_source_directory( $source, $remote_source, $upgrader, $hook_extra ) {
		if ( empty( $hook_extra['plugin'] ) || $hook_extra['plugin'] !== plugin_basename( WPMA_PLUGIN_FILE ) ) {
			return $source;
		}

		global $wp_filesystem;
		if ( ! $wp_filesystem ) {
			return $source;
		}

		$target = trailingslashit( $remote_source ) . dirname( plugin_basename( WPMA_PLUGIN_FILE ) );
		if ( trailingslashit( $source ) === trailingslashit( $target ) ) {
			return $source;
		}
		if ( $wp_filesystem->exists( $target ) ) {
			$wp_filesystem->delete( $target, true );
		}
		if ( $wp_filesystem->move( $source, $target ) ) {
			return $target;
		}
		return $source;
	}

	public static function clear_cache() {
		delete_site_transient( self::CACHE_KEY );
	}

	private static function latest_release( $force = false ) {
		$repo = self::repo();
		if ( ! $repo ) {
			return array();
		}

		if ( ! $force ) {
			$cached = get_site_transient( self::CACHE_KEY );
			if ( is_array( $cached ) ) {
				return $cached;
			}
		}

		$response = wp_remote_get(
			'https://api.github.com/repos/' . rawurlencode( $repo['owner'] ) . '/' . rawurlencode( $repo['repo'] ) . '/releases/latest',
			array(
				'timeout' => 12,
				'headers' => array(
					'Accept'     => 'application/vnd.github+json',
					'User-Agent' => 'WPMA/' . WPMA_VERSION . '; ' . home_url(),
				),
			)
		);

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return array();
		}

		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $body ) || ! empty( $body['draft'] ) || ! empty( $body['prerelease'] ) ) {
			return array();
		}

		$version = self::normalize_version( (string) ( $body['tag_name'] ?? $body['name'] ?? '' ) );
		if ( ! $version ) {
			return array();
		}

		$release = array(
			'version'      => $version,
			'html_url'     => esc_url_raw( (string) ( $body['html_url'] ?? self::repo_url() ) ),
			'package'      => self::package_url( $body ),
			'published_at' => sanitize_text_field( (string) ( $body['published_at'] ?? '' ) ),
			'body'         => wp_strip_all_tags( (string) ( $body['body'] ?? '' ) ),
		);

		set_site_transient( self::CACHE_KEY, $release, self::CACHE_TTL );
		return $release;
	}

	private static function package_url( $release ) {
		$asset_name = defined( 'WPMA_GITHUB_ASSET_NAME' ) ? (string) WPMA_GITHUB_ASSET_NAME : '';
		foreach ( (array) ( $release['assets'] ?? array() ) as $asset ) {
			$name = (string) ( $asset['name'] ?? '' );
			if ( '' !== $asset_name && $name !== $asset_name ) {
				continue;
			}
			if ( '' === $asset_name && ! preg_match( '/\.zip$/i', $name ) ) {
				continue;
			}
			return esc_url_raw( (string) ( $asset['browser_download_url'] ?? '' ) );
		}
		return esc_url_raw( (string) ( $release['zipball_url'] ?? '' ) );
	}

	private static function normalize_version( $tag ) {
		if ( preg_match( '/v?(\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?)/', trim( $tag ), $matches ) ) {
			return $matches[1];
		}
		return '';
	}

	private static function repo() {
		$value = defined( 'WPMA_GITHUB_REPO' ) ? (string) WPMA_GITHUB_REPO : '';
		if ( ! preg_match( '~^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$~', $value, $matches ) ) {
			return array();
		}
		return array( 'owner' => $matches[1], 'repo' => $matches[2] );
	}

	private static function repo_url() {
		$repo = self::repo();
		return $repo ? 'https://github.com/' . rawurlencode( $repo['owner'] ) . '/' . rawurlencode( $repo['repo'] ) : '';
	}
}
