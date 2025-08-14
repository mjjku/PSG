<?php

/**
 * Validates if a string is a valid IP address (IPv4 or IPv6).
 *
 * @param string $string The string to check.
 * @return bool True if it's a valid IP, false otherwise.
 */
function is_ip(string $string): bool
{
    // Use PHP's built-in, highly optimized filter. It's faster and more accurate than regex.
    return filter_var($string, FILTER_VALIDATE_IP) !== false;
}

/**
 * Parses a key-value string (one pair per line, separated by '=') into an associative array.
 *
 * @param string $input The input string.
 * @return array The parsed data.
 */
function parse_key_value_string(string $input): array
{
    $data = [];
    // Use PREG_SPLIT_NO_EMPTY to ignore empty lines.
    $lines = preg_split('/\\R/', $input, -1, PREG_SPLIT_NO_EMPTY);

    foreach ($lines as $line) {
        // Explode with a limit of 2, in case the value contains an '='.
        $parts = explode('=', $line, 2);
        if (count($parts) === 2) {
            $key = trim($parts[0]);
            $value = trim($parts[1]);
            // Ensure key and value are not empty after trimming.
            if ($key !== '' && $value !== '') {
                $data[$key] = $value;
            }
        }
    }
    return $data;
}

/**
 * Gets geolocation information for an IP or hostname.
 *
 * @param string $ipOrHost The IP address or hostname to look up.
 * @return ?stdClass An object with country information, or null on failure.
 */
function ip_info(string $ipOrHost): ?stdClass
{
    // First, check if it's a Cloudflare IP. If so, we can stop and return 'CF'.
    // This check is very fast because it uses a local cache.
    // Note: We need the final IP, so we resolve hostnames first.

    $ip = $ipOrHost;
    // Resolve hostname to IP if needed.
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        // Use '@' to suppress warnings on invalid domains.
        $ip_records = @dns_get_record($ip, DNS_A);
        if (empty($ip_records)) {
            return null; // Failed to resolve hostname
        }
        $ip = $ip_records[array_rand($ip_records)]["ip"];
    }

    // Now check if the resolved IP is from Cloudflare.
    if (is_cloudflare_ip($ip)) {
        return (object) [
            "country" => "CF", // Cloudflare network
        ];
    }
    
    // If not Cloudflare, proceed with geo-lookup APIs.

    // API endpoint configuration [url_template, country_code_key]
    $endpoints = [
        ['https://ipapi.co/{ip}/json/', 'country_code'],
        ['https://ipwho.is/{ip}', 'country_code'], // Note: ipwhois.app has been rebranded to ipwho.is
        ['http://www.geoplugin.net/json.gp?ip={ip}', 'geoplugin_countryCode'],
    ];

    $options = [
        'http' => [
            'method' => 'GET',
            'header' => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n",
            'timeout' => 3, // 3 second timeout is plenty
            'ignore_errors' => true, // Allows reading response body on 4xx/5xx errors
        ],
    ];
    $context = stream_context_create($options);

    foreach ($endpoints as [$url_template, $country_key]) {
        $url = str_replace('{ip}', urlencode($ip), $url_template);
        $response = @file_get_contents($url, false, $context);

        if ($response !== false) {
            $data = json_decode($response);
            if (json_last_error() === JSON_ERROR_NONE && isset($data->{$country_key})) {
                return (object) [
                    "country" => $data->{$country_key} ?? 'XX',
                ];
            }
        }
    }

    // Return default if all endpoints fail.
    return (object) ["country" => "XX"];
}

/**
 * Checks if a given IP address belongs to Cloudflare.
 *
 * This function fetches Cloudflare's official IP lists, caches them locally,
 * and checks the given IP against the CIDR ranges.
 *
 * @param string $ip The IP address to check.
 * @param string $cacheFile The path to the cache file.
 * @param int $cacheDuration The cache duration in seconds (e.g., 86400 for 24 hours).
 * @return bool True if the IP is a Cloudflare IP, false otherwise.
 */
function is_cloudflare_ip(string $ip, string $cacheFile = 'cloudflare_ips.json', int $cacheDuration = 86400): bool
{
    // Check if the provided string is a valid IP address
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return false;
    }

    $ipRanges = [];

    // Check if a valid cache file exists
    if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < $cacheDuration) {
        $ipRanges = json_decode(file_get_contents($cacheFile), true);
    } else {
        // Fetch fresh lists from Cloudflare if cache is old or doesn't exist
        $ipv4 = @file_get_contents('https://www.cloudflare.com/ips-v4');
        $ipv6 = @file_get_contents('https://www.cloudflare.com/ips-v6');

        if ($ipv4 && $ipv6) {
            $ipv4Ranges = explode("\n", trim($ipv4));
            $ipv6Ranges = explode("\n", trim($ipv6));
            $ipRanges = array_merge($ipv4Ranges, $ipv6Ranges);
            // Save the fresh list to the cache file
            file_put_contents($cacheFile, json_encode($ipRanges));
        } else {
             // Fallback to old cache if fetch fails to prevent service disruption
            if (file_exists($cacheFile)) {
                 $ipRanges = json_decode(file_get_contents($cacheFile), true);
            }
        }
    }

    if (empty($ipRanges)) {
        // Could not load ranges from cache or network
        return false;
    }

    foreach ($ipRanges as $range) {
        if (ip_in_cidr($ip, $range)) {
            return true;
        }
    }

    return false;
}

/**
 * Helper function to check if an IP is within a CIDR range.
 * Supports both IPv4 and IPv6.
 *
 * @param string $ip The IP address.
 * @param string $cidr The CIDR range.
 * @return bool
 */
function ip_in_cidr(string $ip, string $cidr): bool
{
    // Make sure CIDR is valid
    if (strpos($cidr, '/') === false) {
        // Handle cases where Cloudflare list might just be an IP
        return $ip === $cidr;
    }
    
    list($net, $mask) = explode('/', $cidr);

    $ip_net = inet_pton($ip);
    $net_net = inet_pton($net);
    
    if ($ip_net === false || $net_net === false) {
        return false;
    }

    $ip_len = strlen($ip_net);
    $net_len = strlen($net_net);

    if ($ip_len !== $net_len) {
        return false; // Mismatch between IPv4/IPv6
    }
    
    // Create a mask string of the correct length
    $mask_bin = str_repeat('1', $mask) . str_repeat('0', ($ip_len * 8) - $mask);
    $mask_net = '';
    // Convert binary mask string to packed binary
    foreach (str_split($mask_bin, 8) as $byte) {
        $mask_net .= chr(bindec($byte));
    }

    return ($ip_net & $mask_net) === ($net_net & $mask_net);
}


/**
 * Checks if the input string contains invalid characters.
 *
 * @param string $input
 * @return bool True if valid, false otherwise.
 */
function is_valid(string $input): bool
{
    // Combined check is slightly more efficient.
    return !(str_contains($input, '…') || str_contains($input, '...'));
}


/**
 * Determines if a proxy configuration is encrypted.
 *
 * @param string $input The configuration link.
 * @return bool
 */
function isEncrypted(string $input): bool
{
    $configType = detect_type($input);

    switch ($configType) {
        case 'vmess':
            $decodedConfig = configParse($input);
            // Ensure keys exist before accessing.
            return ($decodedConfig['tls'] ?? '') !== '' && ($decodedConfig['scy'] ?? 'none') !== 'none';

        case 'vless':
        case 'trojan':
            // Fast check without full parsing.
            return str_contains($input, 'security=tls') || str_contains($input, 'security=reality');
        
        case 'ss':
        case 'tuic':
        case 'hy2':
            // These protocols are inherently encrypted.
            return true;

        default:
            return false;
    }
}


/**
 * Converts a 2-letter country code to a regional flag emoji.
 *
 * @param string $country_code
 * @return string
 */
function getFlags(string $country_code): string
{
    $country_code = strtoupper(trim($country_code));
    if (strlen($country_code) !== 2 || !ctype_alpha($country_code) || $country_code === "XX") {
        return '🏳️'; // Return a default flag for invalid codes.
    }

    $regional_offset = 127397;
    $char1 = mb_convert_encoding('&#' . ($regional_offset + ord($country_code[0])) . ';', 'UTF-8', 'HTML-ENTITIES');
    $char2 = mb_convert_encoding('&#' . ($regional_offset + ord($country_code[1])) . ';', 'UTF-8', 'HTML-ENTITIES');
    
    return $char1 . $char2;
}

/**
 * Detects the proxy protocol type from a configuration link.
 * Uses modern str_starts_with() for readability and performance.
 *
 * @param string $input
 * @return string|null
 */
function detect_type(string $input): ?string
{
    if (str_starts_with($input, 'vmess://')) return 'vmess';
    if (str_starts_with($input, 'vless://')) return 'vless';
    if (str_starts_with($input, 'trojan://')) return 'trojan';
    if (str_starts_with($input, 'ss://')) return 'ss';
    if (str_starts_with($input, 'tuic://')) return 'tuic';
    if (str_starts_with($input, 'hy2://') || str_starts_with($input, 'hysteria2://')) return 'hy2';
    if (str_starts_with($input, 'hysteria://')) return 'hysteria';
    
    return null;
}

/**
 * Extracts all valid proxy links from a given text based on a master list of types.
 * This pattern is designed to be robust and avoid partial matches.
 *
 * @param string $text The input text (e.g., HTML content) to search within.
 * @return array An array of found proxy links.
 */
function extractLinksByType(string $text): array
{
    // Master list of all valid protocol schemes your project supports.
    $valid_types = ['vmess', 'vless', 'trojan', 'ss', 'tuic', 'hy2', 'hysteria'];
    
    // Build the core part of the pattern: (vmess|vless|trojan|...)
    $type_pattern = implode('|', $valid_types);
    
    // The final regex pattern, translated directly from the JavaScript version.
    // We use '/i' for case-insensitivity. preg_match_all is inherently "global".
    $pattern = "/(?:{$type_pattern}):\\/\\/[^\\s\"']*(?=\\s|<|>|$)/i";
    
    // Execute the regex and find all matches.
    preg_match_all($pattern, $text, $matches);
    
    // $matches[0] contains the array of full string matches.
    // If no matches are found, it will be an empty array, which is the desired outcome.
    return $matches[0] ?? [];
}

/**
 * Parses a configuration link into an associative array.
 *
 * @param string $input The configuration link.
 * @return array|null The parsed configuration or null on failure.
 */
function configParse(string $input): ?array
{
    $configType = detect_type($input);

    switch ($configType) {
        case 'vmess':
            $base64_data = substr($input, 8);
            return json_decode(base64_decode($base64_data), true);

        case 'vless':
        case 'trojan':
        case 'tuic':
        case 'hy2':
            $parsedUrl = parse_url($input);
            if ($parsedUrl === false) return null;
            
            $params = [];
            if (isset($parsedUrl['query'])) {
                parse_str($parsedUrl['query'], $params);
            }
            
            $output = [
                'protocol' => $configType,
                'username' => $parsedUrl['user'] ?? '',
                'hostname' => $parsedUrl['host'] ?? '',
                'port' => $parsedUrl['port'] ?? '',
                'params' => $params,
                'hash' => isset($parsedUrl['fragment']) ? rawurldecode($parsedUrl['fragment']) : 'PSG' . getRandomName(),
            ];

            if ($configType === 'tuic') {
                $output['pass'] = $parsedUrl['pass'] ?? '';
            }
            return $output;

        case 'ss':
            $parsedUrl = parse_url($input);
            if ($parsedUrl === false) return null;

            $userInfo = rawurldecode($parsedUrl['user'] ?? '');
            
            // Handle Base64 encoded user info part
            if (isBase64($userInfo)) {
                $userInfo = base64_decode($userInfo);
            }

            if (!str_contains($userInfo, ':')) return null; // Invalid format
            
            list($method, $password) = explode(':', $userInfo, 2);

            return [
                'encryption_method' => $method,
                'password' => $password,
                'server_address' => $parsedUrl['host'] ?? '',
                'server_port' => $parsedUrl['port'] ?? '',
                'name' => isset($parsedUrl['fragment']) ? rawurldecode($parsedUrl['fragment']) : 'PSG' . getRandomName(),
            ];
            
        default:
            return null;
    }
}

/**
 * Rebuilds a configuration link from a parsed array.
 *
 * @param array $configArray
 * @param string $configType
 * @return string|null
 */
function reparseConfig(array $configArray, string $configType): ?string
{
    switch ($configType) {
        case 'vmess':
            $encoded_data = rtrim(strtr(base64_encode(json_encode($configArray)), '+/', '-_'), '=');
            return "vmess://" . $encoded_data;
        
        case 'vless':
        case 'trojan':
        case 'tuic':
        case 'hy2':
            $url = $configType . "://";
            // User and optional password
            if (!empty($configArray['username'])) {
                $url .= $configArray['username'];
                if (!empty($configArray['pass'])) {
                    $url .= ':' . $configArray['pass'];
                }
                $url .= '@';
            }
            $url .= $configArray['hostname'];
            // Port
            if (!empty($configArray['port'])) {
                $url .= ':' . $configArray['port'];
            }
            // Query parameters
            if (!empty($configArray['params'])) {
                $url .= '?' . http_build_query($configArray['params']);
            }
            // Fragment/hash
            if (!empty($configArray['hash'])) {
                // rawurlencode is the correct function for fragments.
                $url .= '#' . rawurlencode($configArray['hash']);
            }
            return $url;

        case 'ss':
            $user_info = base64_encode($configArray['encryption_method'] . ':' . $configArray['password']);
            $url = "ss://{$user_info}@{$configArray['server_address']}:{$configArray['server_port']}";
            if (!empty($configArray['name'])) {
                $url .= '#' . rawurlencode($configArray['name']);
            }
            return $url;

        default:
            return null;
    }
}

/**
 * Checks if a VLESS config uses the 'reality' security protocol.
 *
 * @param string $input
 * @return bool
 */
function is_reality(string $input): bool
{
    // A fast string check is sufficient and avoids parsing.
    return str_starts_with($input, 'vless://') && str_contains($input, 'security=reality');
}

/**
 * Checks if a string is Base64 encoded.
 *
 * @param string $input
 * @return bool
 */
function isBase64(string $input): bool
{
    // The strict parameter ensures the input contains only valid Base64 characters.
    return base64_decode($input, true) !== false;
}

/**
 * Generates a cryptographically secure random name.
 *
 * @param int $length
 * @return string
 */
function getRandomName(int $length = 10): string
{
    // Using random_int is more secure than rand().
    $alphabet = 'abcdefghijklmnopqrstuvwxyz';
    $max = strlen($alphabet) - 1;
    $name = '';
    for ($i = 0; $i < $length; $i++) {
        $name .= $alphabet[random_int(0, $max)];
    }
    return $name;
}

/**
 * Recursively deletes a folder and its contents.
 *
 * @param string $folder The path to the folder.
 * @return bool True on success, false on failure.
 */
function deleteFolder(string $folder): bool
{
    if (!is_dir($folder)) {
        return false;
    }

    // Use modern iterators for better performance and clarity.
    $iterator = new RecursiveDirectoryIterator($folder, RecursiveDirectoryIterator::SKIP_DOTS);
    $files = new RecursiveIteratorIterator($iterator, RecursiveIteratorIterator::CHILD_FIRST);

    foreach ($files as $file) {
        if ($file->isDir()) {
            rmdir($file->getRealPath());
        } else {
            unlink($file->getRealPath());
        }
    }

    return rmdir($folder);
}

/**
 * Gets the current time in the Asia/Tehran timezone.
 *
 * @param string $format The desired date/time format.
 * @return string The formatted time string.
 */
function tehran_time(string $format = 'Y-m-d H:i:s'): string
{
    // This is safer than date_default_timezone_set() as it doesn't affect global state.
    try {
        $date = new DateTime('now', new DateTimeZone('Asia/Tehran'));
        return $date->format($format);
    } catch (Exception $e) {
        // Fallback in case of an error.
        return date($format);
    }
}

/**
 * Generates a Hiddify-compatible subscription header.
 * Uses NOWDOC syntax for clean, multi-line string.
 *
 * @param string $subscriptionName
 * @return string
 */
function hiddifyHeader(string $subscriptionName): string
{
    $base64Name = base64_encode($subscriptionName);
    return <<<HEADER
#profile-title: base64:{$base64Name}
#profile-update-interval: 1
#subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531
#support-url: https://t.me/yebekhe
#profile-web-page-url: https://github.com/yasi-python/PSG

HEADER;
}

/**
 * INTERNAL FUNCTION: Fetches a single batch of URLs in parallel.
 * This is the core worker function that will be called by the retry wrapper.
 *
 * @param array $urls An associative array of [key => url].
 * @return array An associative array of [key => content] for successful fetches.
 *               Failed fetches will be missing from the returned array.
 */
function _internal_fetch_batch(array $urls): array
{
    $multi_handle = curl_multi_init();
    $handles = [];
    $results = [];

    if (empty($urls)) {
        return [];
    }

    foreach ($urls as $key => $url) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_CONNECTTIMEOUT => 10, // Good practice to add a connection timeout
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            CURLOPT_SSL_VERIFYPEER => false, // Be cautious with these in production
            CURLOPT_SSL_VERIFYHOST => false,
        ]);
        $handles[$key] = $ch;
        curl_multi_add_handle($multi_handle, $ch);
    }

    $running = null;
    do {
        curl_multi_exec($multi_handle, $running);
        if ($running) {
            curl_multi_select($multi_handle);
        }
    } while ($running > 0);

    foreach ($handles as $key => $ch) {
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $content = curl_multi_getcontent($ch);
        
        if (curl_errno($ch) === 0 && $http_code === 200 && !empty($content)) {
            $results[$key] = $content;
        }
        // No 'else' here. The calling function will determine what failed by comparing arrays.
        
        curl_multi_remove_handle($multi_handle, $ch);
        curl_close($ch);
    }

    curl_multi_close($multi_handle);
    return $results;
}


/**
 * PUBLIC FUNCTION: Fetches multiple URLs in parallel with a retry mechanism.
 * This is the new function that your Stage 1 script will call.
 *
 * @param array $urls An associative array of [key => url].
 * @param int $max_retries The maximum number of attempts for each URL.
 * @param int $delay The delay in seconds between retry attempts.
 * @return array An associative array of [key => content] containing all successfully fetched content.
 */
function fetch_multiple_urls_parallel(array $urls, int $max_retries = 3, int $delay = 2): array
{
    $all_fetched_content = [];
    $urls_to_retry = $urls;

    for ($attempt = 1; $attempt <= $max_retries; $attempt++) {
        // If there are no URLs left to fetch, we can stop early.
        if (empty($urls_to_retry)) {
            break;
        }

        echo "\n  - Fetch attempt #{$attempt} for " . count($urls_to_retry) . " URLs...";
        
        // Call our internal worker function to fetch the current batch.
        $fetched_this_round = _internal_fetch_batch($urls_to_retry);
        
        // Add the newly fetched content to our master list of results.
        $all_fetched_content = array_merge($all_fetched_content, $fetched_this_round);

        // Determine which URLs failed and need to be retried.
        // This is done by finding which keys exist in the original list but not in the results.
        $urls_to_retry = array_diff_key($urls_to_retry, $fetched_this_round);

        // If some URLs failed and this isn't the last attempt, wait before retrying.
        if (!empty($urls_to_retry) && $attempt < $max_retries) {
            echo PHP_EOL . "  [!] " . count($urls_to_retry) . " URLs failed. Retrying in {$delay} seconds..." . PHP_EOL;
            sleep($delay);
        }
    }
    
    // After all attempts, if any URLs still failed, log them as a critical warning.
    if (!empty($urls_to_retry)) {
        echo PHP_EOL . "  [!!] CRITICAL WARNING: The following URLs failed after all attempts:" . PHP_EOL;
        foreach (array_keys($urls_to_retry) as $failed_key) {
            echo "      - {$failed_key}" . PHP_EOL;
        }
    }

    return $all_fetched_content;
}

/**
 * Prints a clean, overwriting progress bar to the console.
 * @param int $current
 * @param int $total
 * @param string $message
 */
function print_progress(int $current, int $total, string $message = ''): void
{
    if ($total == 0) return;
    $percentage = ($current / $total) * 100;
    $bar_length = 50;
    $filled_length = (int)($bar_length * $current / $total);
    $bar = str_repeat('=', $filled_length) . str_repeat(' ', $bar_length - $filled_length);
    printf("\r%s [%s] %d%% (%d/%d)", $message, $bar, $percentage, $current, $total);
}

// #############################################################################
// The Core Abstraction: A Wrapper Class for Different Config Types
// #############################################################################

class ConfigWrapper
{
    private ?array $decoded;
    private string $type;

    public function __construct(string $config_string)
    {
        $this->type = detect_type($config_string) ?? 'unknown';
        $this->decoded = configParse($config_string);
    }

    public function isValid(): bool
    {
        return $this->decoded !== null;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getTag(): string
    {
        $field = match($this->type) {
            'vmess' => 'ps',
            'ss' => 'name',
            default => 'hash',
        };
        return urldecode($this->decoded[$field] ?? 'Unknown Tag');
    }

    public function getServer(): string
    {
        return match($this->type) {
            'vmess' => $this->decoded['add'],
            'ss' => $this->decoded['server_address'],
            default => $this->decoded['hostname'],
        };
    }

    public function getPort(): int
    {
        $port = match($this->type) {
            'ss' => $this->decoded['server_port'],
            default => $this->decoded['port'],
        };
        return (int)$port;
    }

    public function getUuid(): string
    {
        return match($this->type) {
            'vmess' => $this->decoded['id'],
            'vless', 'trojan' => $this->decoded['username'],
            'tuic' => $this->decoded['username'],
            default => '',
        };
    }

    public function getPassword(): string
    {
        return match($this->type) {
            'trojan' => $this->decoded['username'],
            'ss' => $this->decoded['password'],
            'tuic' => $this->decoded['pass'],
            'hy2' => $this->decoded['username'],
            default => '',
        };
    }

    public function getSni(): string
    {
        return match($this->type) {
            'vmess' => $this->decoded['sni'] ?? $this->getServer(),
            default => $this->decoded['params']['sni'] ?? $this->getServer(),
        };
    }

    public function getTransportType(): ?string
    {
        return match($this->type) {
            'vmess' => $this->decoded['net'],
            default => $this->decoded['params']['type'] ?? null,
        };
    }
    
    public function getPath(): string
    {
        $path = match($this->type) {
            'vmess' => $this->decoded['path'] ?? '/',
            default => $this->decoded['params']['path'] ?? '/',
        };
        return '/' . ltrim($path, '/');
    }

    public function getServiceName(): string
    {
        return match($this->type) {
            'vmess' => $this->decoded['path'] ?? '',
            default => $this->decoded['params']['serviceName'] ?? '',
        };
    }

    // Pass through direct access to the decoded array for complex cases
    public function get(string $key, $default = null)
    {
        return $this->decoded[$key] ?? $default;
    }
    
    public function getParam(string $key, $default = null)
    {
        return $this->decoded['params'][$key] ?? $default;
    }
}

/**
 * Validates if a string is a valid Version 4 UUID.
 *
 * @param string|null $uuid The string to check.
 * @return bool True if valid, false otherwise.
 */
function is_valid_uuid(?string $uuid): bool
{
    if ($uuid === null) {
        return false;
    }
    
    // This regex is a standard and reliable pattern for V4 UUIDs.
    $pattern = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';
    
    return (bool) preg_match($pattern, $uuid);
}

/**
 * Fetches multiple pages of a Telegram channel until the page limit is reached or no more pages are available.
 *
 * @param string $channelName The username of the channel.
 * @param int $maxPages The maximum number of pages to fetch.
 * @return string The combined HTML content of all fetched pages.
 */
function fetch_channel_data_paginated(string $channelName, int $maxPages): string
{
    $combinedHtml = '';
    $nextUrl = "https://t.me/s/{$channelName}";
    $fetchedPages = 0;

    while ($fetchedPages < $maxPages && $nextUrl) {
        echo "\rFetching page " . ($fetchedPages + 1) . "/{$maxPages} for channel '{$channelName}'... ";
        
        $response = @file_get_contents($nextUrl, false, stream_context_create([
            'http' => [
                'timeout' => 15,
                'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            ]
        ]));

        if ($response === false || empty($response)) {
            // Stop paginating for this channel if a request fails
            $nextUrl = null;
            continue;
        }

        $combinedHtml .= $response;

        // Find the oldest message ID on the page to build the next page URL
        preg_match_all('/data-post="[^"]+\/(\d+)"/', $response, $matches);
        
        if (!empty($matches[1])) {
            $oldestMessageId = min($matches[1]);
            $nextUrl = "https://t.me/s/{$channelName}?before={$oldestMessageId}";
        } else {
            // No more message IDs found, so it's the last page
            $nextUrl = null;
        }
        $fetchedPages++;
    }

    return $combinedHtml;
}
