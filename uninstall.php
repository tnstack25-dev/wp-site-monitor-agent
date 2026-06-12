<?php
/**
 * Uninstall cleanup for WP Site Monitor Agent.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'wpma_settings' );
delete_option( 'wpma_last_report_at' );
delete_transient( 'wpma_access_log_error' );
wp_clear_scheduled_hook( 'wpma_access_log_cleanup' );
wp_clear_scheduled_hook( 'wpma_send_scheduled_report' );
