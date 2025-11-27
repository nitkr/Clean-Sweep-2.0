<?php
/**
 * Clean Sweep - Plugin Utility Functions
 *
 * Shared utility functions for plugin operations
 */

/**
 * Format timestamp as relative time (e.g., "2 days ago", "3 months ago")
 * Properly handles UTC timestamps from WordPress.org API
 */
function clean_sweep_format_relative_time($timestamp) {
    if (!$timestamp) {
        return 'Unknown';
    }

    $now = new DateTime('now', new DateTimeZone('UTC'));
    $plugin_time = new DateTime($timestamp, new DateTimeZone('UTC'));
    $diff = $now->getTimestamp() - $plugin_time->getTimestamp();

    if ($diff < 0) {
        return 'Future';
    }

    $intervals = [
        31536000 => 'year',
        2592000 => 'month',
        604800 => 'week',
        86400 => 'day',
        3600 => 'hour',
        60 => 'minute'
    ];

    foreach ($intervals as $seconds => $unit) {
        $count = floor($diff / $seconds);
        if ($count > 0) {
            $plural = $count > 1 ? 's' : '';
            return $count . ' ' . $unit . $plural . ' ago';
        }
    }

    return 'Just now';
}

/**
 * Fetch additional plugin information from WordPress.org API
 */
function clean_sweep_fetch_plugin_info($slug) {
    // Suppress all errors and warnings during API call
    $error_reporting = error_reporting(0);

    try {
        $api_url = "https://api.wordpress.org/plugins/info/1.0/$slug.json";
        $response = @wp_remote_get($api_url, ['timeout' => 5]); // Reduced timeout

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return [];
        }

        $data = @json_decode(wp_remote_retrieve_body($response), true);
        if (!$data) {
            return [];
        }

        return [
            'last_updated' => $data['last_updated'] ?? null,
            'homepage' => $data['homepage'] ?? null,
            'version' => $data['version'] ?? null,
            'requires' => $data['requires'] ?? null,
            'tested' => $data['tested'] ?? null,
            'rating' => $data['rating'] ?? null,
            'num_ratings' => $data['num_ratings'] ?? null
        ];
    } catch (Exception $e) {
        return [];
    } finally {
        // Restore error reporting
        error_reporting($error_reporting);
    }
}

/**
 * Check if a plugin path corresponds to a WordPress.org repository plugin
 */
/**
 * Check if a plugin is managed by WPMU DEV dashboard
 * Uses the same detection method as the Dashboard: checks for WDP ID header
 */
function clean_sweep_is_wpmudev_plugin($plugin_path) {
    // First, check if the plugin file has the WDP ID header (most reliable method)
    if (file_exists($plugin_path)) {
        $plugin_data = get_file_data(
            $plugin_path,
            array(
                'name'    => 'Plugin Name',
                'id'      => 'WDP ID',
                'version' => 'Version',
            )
        );

        if (!empty($plugin_data['id']) && is_numeric($plugin_data['id'])) {
            clean_sweep_log_message("DEBUG WPMU DEV: Found WDP ID header: {$plugin_data['id']} in {$plugin_path}", 'info');
            return true;
        }
    }

    // Fallback: Check if WPMU DEV Dashboard class exists
    if (!class_exists('WPMUDEV_Dashboard')) {
        return false;
    }

    // Get plugin basename for comparison
    $plugin_basename = plugin_basename($plugin_path);
    $plugin_dir = dirname($plugin_basename);
    if ($plugin_dir === '.') {
        // Single-file plugin
        $plugin_dir = pathinfo(basename($plugin_path), PATHINFO_FILENAME);
    } else {
        $plugin_dir = basename($plugin_dir);
    }

    clean_sweep_log_message("DEBUG WPMU DEV: Checking plugin_path={$plugin_path}, plugin_basename={$plugin_basename}, plugin_dir={$plugin_dir}", 'info');

    // Get WPMU DEV dashboard instance
    $dashboard = WPMUDEV_Dashboard::instance();
    if (!$dashboard) {
        return false;
    }

    $site = WPMUDEV_Dashboard::$site;
    if (!$site) {
        return false;
    }

    try {
        // Always refresh the cache before checking (ensures fresh data after reinstall)
        $site->refresh_local_projects('local');

        // Get all projects
        $projects = $site->get_cached_projects();
        clean_sweep_log_message("DEBUG WPMU DEV: Found " . count($projects) . " WPMU DEV projects after refresh", 'info');

        // Check if the plugin filename matches any project
        foreach ((array) $projects as $project_id => $project) {
            if (empty($project['filename']) || ($project['type'] ?? '') !== 'plugin') {
                continue;
            }

            $project_filename = $project['filename'];
            $project_dir = dirname($project_filename);
            if ($project_dir === '.') {
                $project_dir = pathinfo($project_filename, PATHINFO_FILENAME);
            } else {
                $project_dir = basename($project_dir);
            }

            // Compare both the full filename and the directory name
            if ($project_filename === $plugin_basename || $project_dir === $plugin_dir) {
                clean_sweep_log_message("DEBUG WPMU DEV: MATCH FOUND - Project ID {$project_id}, filename: {$project_filename}", 'info');
                return true;
            }
        }
    } catch (Exception $e) {
        clean_sweep_log_message("DEBUG WPMU DEV: Exception during check: " . $e->getMessage(), 'error');
        return false;
    }

    clean_sweep_log_message("DEBUG WPMU DEV: No match found for {$plugin_basename}", 'info');
    return false;
}
