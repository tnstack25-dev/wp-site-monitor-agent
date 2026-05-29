<?php
/**
 * Plugin Name: WP Site Monitor Agent
 * Description: Child agent for WP Site Monitor Manager: signed health checks and remote malware scanning.
 * Version: 1.0.0
 * Author: TNStack
 * Author URI: https://tnstack.com
 * Text Domain: wp-site-monitor-agent
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WPMA_VERSION', '1.0.0' );
define( 'WPMA_PLUGIN_FILE', __FILE__ );
define( 'WPMA_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPMA_GITHUB_REPO', 'tnstack25-dev/wp-site-monitor-agent' );

require_once WPMA_PLUGIN_DIR . 'includes/class-wpma-plugin.php';
require_once WPMA_PLUGIN_DIR . 'includes/class-wpma-github-updater.php';

register_activation_hook( __FILE__, array( 'WPMA_Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'WPMA_Plugin', 'deactivate' ) );

add_action( 'plugins_loaded', array( 'WPMA_Plugin', 'init' ) );
add_action( 'plugins_loaded', array( 'WPMA_GitHub_Updater', 'register' ) );
