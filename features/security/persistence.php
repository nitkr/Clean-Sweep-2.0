<?php
/**
 * Clean Sweep - MySQL Persistence Detection
 *
 * Advanced detection of server-level malware persistence mechanisms
 * Checks for database triggers, events, and other server-side persistence
 */

/**
 * MySQL Persistence Detection Class
 * Detects advanced malware persistence techniques at database server level
 */
class Clean_Sweep_Persistence_Detector {

    /**
     * Check for server-level persistence mechanisms
     */
    public function scan_mysql_persistence() {
        $threats = [];

        // Check for database triggers (very rare, but concerning if found)
        try {
            $triggers = $this->get_database_triggers();
            if (!empty($triggers)) {
                $threats[] = [
                    'pattern' => 'MYSQL_TRIGGER',
                    'match' => count($triggers) . ' database trigger(s) found',
                    'table' => 'MySQL_SERVER',
                    'content_preview' => 'Database-level triggers detected (unusual for WordPress)',
                    'severity' => 'medium',
                    'action' => 'review_manually',
                    'details' => implode('; ', array_column($triggers, 'name'))
                ];
            }
        } catch (Exception $e) {
            // Silently fail if no SHOW permissions
            // This is expected for most hosting providers
        }

        // Check for scheduled events
        try {
            $events = $this->get_database_events();
            if (!empty($events)) {
                $threats[] = [
                    'pattern' => 'MYSQL_EVENT',
                    'match' => count($events) . ' scheduled event(s) found',
                    'table' => 'MySQL_SERVER',
                    'content_preview' => 'Database-level scheduled events detected',
                    'severity' => 'medium',
                    'action' => 'review_manually',
                    'details' => implode('; ', array_column($events, 'name'))
                ];
            }
        } catch (Exception $e) {
            // Silently fail if no permissions
        }

        // Check for stored procedures (less common in WordPress)
        try {
            $procedures = $this->get_stored_procedures();
            if (!empty($procedures)) {
                $threats[] = [
                    'pattern' => 'MYSQL_PROCEDURE',
                    'match' => count($procedures) . ' stored procedure(s) found',
                    'table' => 'MySQL_SERVER',
                    'content_preview' => 'Unexpected stored procedures detected',
                    'severity' => 'low',
                    'action' => 'review_manually',
                    'details' => implode('; ', array_column($procedures, 'name'))
                ];
            }
        } catch (Exception $e) {
            // Silently fail if no permissions
        }

        return $threats;
    }

    /**
     * Get database triggers (if permissions allow)
     */
    private function get_database_triggers() {
        global $wpdb;

        $triggers = [];
        try {
            $results = $wpdb->get_results($wpdb->prepare("SHOW TRIGGERS FROM `%s`", $wpdb->dbname));
            foreach ($results as $trigger) {
                $triggers[] = [
                    'name' => $trigger->Trigger,
                    'table' => $trigger->Table,
                    'event' => $trigger->Event,
                    'timing' => $trigger->Timing
                ];
            }
        } catch (Exception $e) {
            // Expected if no permissions
        }

        return $triggers;
    }

    /**
     * Get database events (if permissions allow)
     */
    private function get_database_events() {
        global $wpdb;

        $events = [];
        try {
            $results = $wpdb->get_results($wpdb->prepare("SHOW EVENTS FROM `%s`", $wpdb->dbname));
            foreach ($results as $event) {
                $events[] = [
                    'name' => $event->Name,
                    'status' => $event->Status,
                    'type' => $event->Type
                ];
            }
        } catch (Exception $e) {
            // Expected if no permissions
        }

        return $events;
    }

    /**
     * Get stored procedures (if permissions allow)
     */
    private function get_stored_procedures() {
        global $wpdb;

        $procedures = [];
        try {
            $results = $wpdb->get_results($wpdb->prepare("SHOW PROCEDURE STATUS WHERE Db = '%s'", $wpdb->dbname));
            foreach ($results as $procedure) {
                // Skip known WordPress/MySQL system procedures
                $system_procedures = [
                    'mysql.proc',
                    'mysql.event'
                ];

                if (!in_array($procedure->Name, $system_procedures)) {
                    $procedures[] = [
                        'name' => $procedure->Name,
                        'type' => $procedure->Type,
                        'definer' => $procedure->Definer
                    ];
                }
            }
        } catch (Exception $e) {
            // Expected if no permissions
        }

        return $procedures;
    }

    /**
     * Check if server-level persistence should be scanned
     */
    public function should_scan_persistence() {
        // Only run if user explicitly enabled this feature (via POST parameter)
        return isset($_POST['check_mysql_persistence']) && $_POST['check_mysql_persistence'] === '1';
    }

    /**
     * Perform persistence scan with results merging
     */
    public function scan_persistence_check($results, $progress_callback = null) {
        // Only run if user explicitly enabled this feature
        if (!$this->should_scan_persistence()) {
            if ($progress_callback) {
                $progress_callback(0, 0, "MySQL persistence check skipped (not enabled)");
            }
            return $results;
        }

        $threats = $this->scan_mysql_persistence();
        if (!isset($results['mysql_persistence'])) {
            $results['mysql_persistence'] = [];
        }
        $results['mysql_persistence'] = array_merge($results['mysql_persistence'], $threats);
        $results['total_scanned'] += 1; // Count as one "item" scanned

        if ($progress_callback) {
            $progress_callback(1, 1, "Checked MySQL persistence mechanisms");
        }

        return $results;
    }

    /**
     * Get persistence check information for UI
     */
    public function get_persistence_info() {
        return [
            'title' => 'MySQL Server Persistence',
            'description' => 'Scans for database triggers/events. May need elevated permissions.',
            'warning' => 'This advanced check requires database permissions most hosts don\'t provide.',
            'options' => $this->get_available_checks(),
            'recommended' => false // Not recommended for most users
        ];
    }

    /**
     * Get available persistence checks
     */
    private function get_available_checks() {
        return [
            'triggers' => 'Database triggers (automatic persistence)',
            'events' => 'Scheduled events (timed persistence)',
            'procedures' => 'Stored procedures (advanced persistence)'
        ];
    }

    /**
     * Check if current user has required permissions for persistence scans
     */
    public function check_permissions() {
        global $wpdb;

        $permissions = [
            'triggers' => false,
            'events' => false,
            'procedures' => false
        ];

        // Test each permission
        try {
            $wpdb->get_results($wpdb->prepare("SHOW TRIGGERS FROM `%s` LIMIT 1", $wpdb->dbname));
            $permissions['triggers'] = true;
        } catch (Exception $e) {}

        try {
            $wpdb->get_results($wpdb->prepare("SHOW EVENTS FROM `%s` LIMIT 1", $wpdb->dbname));
            $permissions['events'] = true;
        } catch (Exception $e) {}

        try {
            $wpdb->get_results($wpdb->prepare("SHOW PROCEDURE STATUS WHERE Db = '%s' LIMIT 1", $wpdb->dbname));
            $permissions['procedures'] = true;
        } catch (Exception $e) {}

        return $permissions;
    }
}

// Initialize persistence detector
$persistence_detector = new Clean_Sweep_Persistence_Detector();
