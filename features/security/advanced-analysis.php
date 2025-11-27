<?php
/**
 * Clean Sweep - Advanced Malware Analysis
 *
 * Methods for detecting obfuscated malware and deconstructed function calls
 */

/**
 * Advanced Malware Analysis Class
 * Contains methods for detecting complex, obfuscated malware techniques
 */
class Clean_Sweep_Advanced_Malware_Analysis {

    /**
     * Analyze content for variable deconstruction attacks
     */
    public function detect_deconstructed_functions($content, $table, $table_context = '') {
        $threats = [];

        // Pattern matching for deconstructed PHP function calls
        $deconstruction_patterns = [
            // Base64 encoded function names in variables
            '/\$[a-zA-Z_]\w*\s*=\s*["\'][A-Za-z0-9+\/=]{15,}["\'];/', // Base64 variable assignment

            // Function calls on deconstructed variables
            '/\$\w+\s*\([^)]*\)\s*;/', // Variable function call

            // Variable in variable calls (${$var})
            '/\$\{\$\w+\}/',

            // Array access function calls (like array_filter exploits)
            '/\$[a-zA-Z_]\w*\s*\[\s*[\'"]\w+[\'"]\s*\]\s*\([^)]*\)/i',

            // Common deconstructed function patterns
            '/base64_decode\s*\(\s*\$/', // Base64 on variable
            '/gzinflate\s*\(\s*\$/', // Gzip on variable
            '/str_rot13\s*\(\s*\$/', // Rot13 on variable
            '/eval\s*\(\s*\$/', // Eval on variable

            // Callback arrays (array_filter, uasort style attacks)
            '/array_filter\s*\(\s*\$/i',
            '/uasort\s*\(\s*\$/i',
            '/usort\s*\(\s*\$/i',

            // Dynamic function creation
            '/create_function\s*\(\s*\$/',

            // Shutdown function registration
            '/register_shutdown_function\s*\(\s*\$/',

            // URL download and execution
            '/file_get_contents\s*\(\s*\$[a-zA-Z_]\w*.*http/i',
        ];

        // Check if content contains deconstruction patterns
        foreach ($deconstruction_patterns as $pattern) {
            if (preg_match($pattern, $content, $matches)) {
                // Verify these are not legitimate code (anti-false-positive)
                if (!$this->is_legitimate_code($content, $matches[0])) {
                    $threats[] = [
                        'pattern' => 'DECONSTRUCTED_FUNCTION_ATTACK',
                        'match' => substr($matches[0], 0, 100),
                        'table' => $table,
                        'content_preview' => substr($content, 0, 200),
                        'threat_level' => 'critical',
                        'attack_type' => 'Variable deconstruction attack',
                        'context' => $table_context
                    ];
                }
            }
        }

        // Look for function name encoding patterns
        if (preg_match_all('/[\'"](([A-Za-z0-9+\/=]){10,})[\'"]/', $content, $b64_matches)) {
            foreach ($b64_matches[1] as $possible_b64) {
                $decoded = @base64_decode(trim($possible_b64), true);
                if ($decoded !== false && $this->is_suspicious_function($decoded)) {
                    $threats[] = [
                        'pattern' => 'ENCODED_FUNCTION_NAME',
                        'match' => 'Base64 encoded: ' . substr($possible_b64, 0, 20) . '...' . ' (' . $decoded . ')',
                        'table' => $table,
                        'content_preview' => substr($content, 0, 200),
                        'threat_level' => 'high',
                        'attack_type' => 'Function name encoding',
                        'context' => $table_context
                    ];
                }
            }
        }

        return $threats;
    }

    /**
     * Check if decoded function name is suspicious
     */
    private function is_suspicious_function($function_name) {
        $suspicious_functions = [
            'create_function',
            'register_shutdown_function',
            'call_user_func',
            'call_user_func_array',
            'assert',
            'eval',
            'exec',
            'system',
            'shell_exec',
            'passthru',
            'popen',
            'proc_open',
            'eval',
            'preg_replace',
            'file_get_contents',
            'urldecode'
        ];

        return in_array(strtolower($function_name), $suspicious_functions);
    }

    /**
     * Advanced multi-layer encoding chain detection
     */
    public function detect_encoding_chains($content, $table, $table_context = '') {
        $threats = [];

        // Skip already detected patterns (avoid double-counting)
        if ($this->contains_malware($content) > 0) {
            return $threats; // Will be caught by regular scanning
        }

        $encoding_result = $this->analyze_encoding_chain($content);

        if ($encoding_result['detected']) {
            $threats[] = [
                'pattern' => 'MULTI_ENCODING_CHAIN',
                'match' => substr($encoding_result['original'], 0, 100),
                'table' => $table,
                'content_preview' => substr($encoding_result['decoded'], 0, 200),
                'encoding_layers' => $encoding_result['layers'],
                'threat_level' => $encoding_result['threat_level'],
                'chain_details' => "Multi-encoded malware ({$encoding_result['layers']} layers)",
                'context' => $table_context
            ];
        }

        return $threats;
    }

    /**
     * Analyze content for encoding chains (up to 6 layers deep)
     */
    private function analyze_encoding_chain($content) {
        $encoding_depth = 0;
        $original = $content;
        $decoded = $content;
        $error_log = [];

        // Try decoding up to 6 layers (covering 99.9% of real malware)
        for ($i = 0; $i < 6; $i++) {
            $previous = $decoded;
            $layer_found = false;

            // Try base64 decode
            if (preg_match('/^[A-Za-z0-9+\/=]+\s*$/', trim($decoded)) &&
                strlen(trim($decoded)) > 20 &&
                strpos($decoded, ' ') === false) {

                $attempt = @base64_decode(str_replace(' ', '', $decoded), true);
                if ($attempt !== false &&
                    $attempt !== $previous &&
                    preg_match('/[\x20-\x7E]/', $attempt)) {

                    $decoded = $attempt;
                    $encoding_depth++;
                    $layer_found = true;
                    $error_log[] = "Base64 decoded (layer $encoding_depth)";
                    continue;
                }
            }

            // Try gzinflate (common compression)
            if (strlen($decoded) > 10 && is_string($decoded)) {
                $attempt = @gzinflate($decoded);
                if ($attempt !== false &&
                    $attempt !== $previous &&
                    strlen($attempt) > 0) {

                    $decoded = $attempt;
                    $encoding_depth++;
                    $layer_found = true;
                    $error_log[] = "GZip inflated (layer $encoding_depth)";
                    continue;
                }
            }

            // Try gzuncompress
            if (strlen($decoded) > 10 && is_string($decoded)) {
                $attempt = @gzuncompress($decoded);
                if ($attempt !== false &&
                    $attempt !== $previous &&
                    strlen($attempt) > 0) {

                    $decoded = $attempt;
                    $encoding_depth++;
                    $layer_found = true;
                    $error_log[] = "GZuncompressed (layer $encoding_depth)";
                    continue;
                }
            }

            // Try gzdeflate
            if (strlen($decoded) > 10 && is_string($decoded)) {
                $attempt = @gzdeflate($decoded);
                if ($attempt !== false &&
                    $attempt !== $previous &&
                    strlen($attempt) > 0) {

                    $decoded = $attempt;
                    $encoding_depth++;
                    $layer_found = true;
                    $error_log[] = "GZdeflate (layer $encoding_depth)";
                    continue;
                }
            }

            // Try str_rot13 (encryption)
            if (preg_match('/[a-zA-Z]/', $decoded)) {
                $attempt = str_rot13($decoded);
                if ($attempt !== $previous &&
                    $this->has_malware_indicators($attempt) &&
                    !$this->has_malware_indicators($decoded)) {

                    $decoded = $attempt;
                    $encoding_depth++;
                    $layer_found = true;
                    $error_log[] = "ROT13 decoded (layer $encoding_depth)";
                    continue;
                }
            }

            // Try hex2bin decode
            if (preg_match('/^[0-9a-f\s]+$/i', trim($decoded)) &&
                strlen(trim($decoded)) % 2 === 0 &&
                strlen(trim($decoded)) > 8) {

                $attempt = @hex2bin(str_replace(' ', '', $decoded));
                if ($attempt !== false &&
                    $attempt !== $previous) {

                    $decoded = $attempt;
                    $encoding_depth++;
                    $layer_found = true;
                    $error_log[] = "Hex decoded (layer $encoding_depth)";
                    continue;
                }
            }

            // Try urldecode for URL-encoded content
            if (preg_match('/%[0-9A-Fa-f]{2}/', $decoded)) {
                $attempt = urldecode($decoded);
                if ($attempt !== $previous && strlen($attempt) > 0) {
                    $decoded = $attempt;
                    $encoding_depth++;
                    $layer_found = true;
                    $error_log[] = "URL decoded (layer $encoding_depth)";
                    continue;
                }
            }

            // Stop if no layer was found
            if (!$layer_found) {
                break;
            }
        }

        // Check if the final decoded content contains malware
        if ($encoding_depth > 0 && $this->has_malware_indicators($decoded)) {
            return [
                'detected' => true,
                'layers' => $encoding_depth,
                'original' => $original,
                'decoded' => $decoded,
                'threat_level' => $encoding_depth >= 2 ? 'critical' : 'high',
                'error_log' => $error_log
            ];
        }

        return ['detected' => false, 'layers' => 0, 'original' => $original, 'decoded' => $decoded];
    }

    /**
     * Check if content has obvious malware indicators
     */
    private function has_malware_indicators($content) {
        $indicators = [
            '/\beval\s*\(/i',
            '/\bexec\s*\(/i',
            '/\bsystem\s*\(/i',
            '/\bshell_exec\s*\(/i',
            '/\bpassthru\s*\(/i',
            '/\bassert\s*\(/i',
            '/\bpreg_replace.*\/e.*?["\']/i',
            '/\bcreate_function\s*\(/i',
            '/\$\w+\s*\([^)]*\)\s*;/', // Variable function calls
            '/<\?php.*eval/i' // PHP tags with eval
        ];

        foreach ($indicators as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Anti-false-positive check for detected malicious patterns
     */
    private function is_legitimate_code($content, $match) {
        // Skip legitimate WordPress code patterns

        // WordPress core functions/variables
        if (preg_match('/wp_.*\$_\w+/i', $content)) {
            return true;
        }

        // Legitimate array_filter usage
        if (preg_match('/array_filter\s*\(\s*\$[a-z_]+\s*,\s*[\'"]strlen[\'"]/i', $content)) {
            return true;
        }

        // Legitimate base64_decode (images, etc.)
        if (preg_match('/data:image.+base64,/i', $content) ||
            preg_match('/src=["\'].*data:image.+base64,/i', $content)) {
            return true;
        }

        // WordPress serialized data
        if (preg_match('/a:\d+:\{/i', $content) && !preg_match('/eval|assert|exec/i', $content)) {
            return true;
        }

        return false;
    }

    /**
     * Check if content contains malware (compatibility method)
     */
    private function contains_malware($content) {
        require_once 'signatures.php';
        $signatures = clean_sweep_get_malware_signatures();

        $results = $signatures->scan_content($content, 'analysis');
        return count($results);
    }

    /**
     * Scan content for deconstructed function patterns
     */
    public function scan_for_deconstructed_functions($results, $progress_callback = null) {
        global $wpdb;

        // Scan potentially suspicious content for deconstructed attack patterns
        $suspicious_content = [];

        // Get large option values that might contain deconstructed malware
        $large_options = $wpdb->get_results(
            "SELECT option_name, option_value FROM {$wpdb->options}
             WHERE LENGTH(option_value) > 1000 AND LENGTH(option_value) < 100000
             LIMIT 100"
        );

        foreach ($large_options as $option) {
            if (!$this->is_known_large_option($option->option_name)) {
                $suspicious_content[] = [
                    'content' => $option->option_value,
                    'table' => 'wp_options',
                    'context' => 'option:' . $option->option_name
                ];
            }
        }

        // Get large postmeta values
        $large_meta = $wpdb->get_results(
            "SELECT post_id, meta_key, meta_value FROM {$wpdb->postmeta}
             WHERE LENGTH(meta_value) > 500 AND meta_key NOT IN ('_edit_lock', '_edit_last')
             LIMIT 200"
        );

        foreach ($large_meta as $meta) {
            if (!$this->is_safe_meta_key($meta->meta_key)) {
                $suspicious_content[] = [
                    'content' => $meta->meta_value,
                    'table' => 'wp_postmeta',
                    'context' => 'post_id:' . $meta->post_id . ',key:' . $meta->meta_key
                ];
            }
        }

        // Get post content that might contain inline scripts
        $post_content = $wpdb->get_results(
            "SELECT ID, post_content FROM {$wpdb->posts}
             WHERE post_status IN ('publish', 'draft', 'private')
             AND LENGTH(post_content) > 1000
             LIMIT 100"
        );

        foreach ($post_content as $post) {
            $suspicious_content[] = [
                'content' => $post->post_content,
                'table' => 'wp_posts',
                'context' => 'post_id:' . $post->ID
            ];
        }

        $results['total_scanned'] += count($suspicious_content);

        foreach ($suspicious_content as $item) {
            $threats = $this->detect_deconstructed_functions($item['content'], $item['table'], $item['context']);
            if (!empty($threats)) {
                if (!isset($results['deconstructed_attacks'])) {
                    $results['deconstructed_attacks'] = [];
                }
                $results['deconstructed_attacks'] = array_merge($results['deconstructed_attacks'], $threats);
            }
        }

        if ($progress_callback) {
            $progress_callback(count($suspicious_content), count($suspicious_content), "Analyzing deconstructed function patterns");
        }

        return $results;
    }

    /**
     * Scan content for multi-encoding chains
     */
    public function scan_for_encoding_chains($results, $progress_callback = null) {
        global $wpdb;

        // Scan potentially suspicious options and postmeta for encoding chains
        $suspicious_content = [];

        // Get large option values that might contain encoding chains
        $large_options = $wpdb->get_results(
            "SELECT option_name, option_value FROM {$wpdb->options}
             WHERE LENGTH(option_value) > 1000 AND LENGTH(option_value) < 100000
             LIMIT 100"
        );

        foreach ($large_options as $option) {
            if (!$this->is_known_large_option($option->option_name)) {
                $suspicious_content[] = [
                    'content' => $option->option_value,
                    'table' => 'wp_options',
                    'context' => 'option:' . $option->option_name
                ];
            }
        }

        // Get large postmeta values
        $large_meta = $wpdb->get_results(
            "SELECT post_id, meta_key, meta_value FROM {$wpdb->postmeta}
             WHERE LENGTH(meta_value) > 500 AND meta_key NOT IN ('_edit_lock', '_edit_last')
             LIMIT 200"
        );

        foreach ($large_meta as $meta) {
            if (!$this->is_safe_meta_key($meta->meta_key)) {
                $suspicious_content[] = [
                    'content' => $meta->meta_value,
                    'table' => 'wp_postmeta',
                    'context' => 'post_id:' . $meta->post_id . ',key:' . $meta->meta_key
                ];
            }
        }

        $results['total_scanned'] += count($suspicious_content);

        foreach ($suspicious_content as $item) {
            $threats = $this->detect_encoding_chains($item['content'], $item['table'], $item['context']);
            if (!empty($threats)) {
                $results['encoding_chains'] = array_merge($results['encoding_chains'], $threats);
            }
        }

        if ($progress_callback) {
            $progress_callback(count($suspicious_content), count($suspicious_content), "Analyzing encoding chains");
        }

        return $results;
    }

    /**
     * Check if a meta key is known to be safe
     */
    private function is_safe_meta_key($meta_key) {
        $safe_keys = [
            '_edit_lock',
            '_edit_last',
            '_thumbnail_id',
            '_wp_page_template',
            '_wp_attached_file',
            '_menu_item_type',
            '_menu_item_object',
            '_menu_item_menu_item_parent'
        ];

        return in_array($meta_key, $safe_keys);
    }

    /**
     * Check if option name is known to contain legitimate large data
     */
    private function is_known_large_option($option_name) {
        $large_options = [
            'cron',
            'update_themes',
            'update_plugins',
            'unzip_file',
            '_site_transient_browser_',
            '_transient_'
        ];

        foreach ($large_options as $pattern) {
            if (strpos($option_name, $pattern) === 0) {
                return true;
            }
        }

        return false;
    }
}
