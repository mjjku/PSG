<?php

declare(strict_types=1);

/**
 * This script reads a list of proxy configurations, sorts them by protocol type
 * AND address type (IPv4, IPv6, Domain), and generates separate subscription
 * files for each combination. It also includes special categories for "reality"
 * and "xhttp" (HTTP Obfuscation) configs, AND a main subscription for each protocol.
 *
 * It now adds specific "fake" configs to the end of every generated subscription file.
 */

// --- Setup ---
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

// Ensure the optimized functions.php is available
require_once __DIR__ . '/functions.php';

// --- Configuration Constants ---
const CONFIG_FILE = __DIR__ . '/config.txt';
const SUBS_DIR_NORMAL = __DIR__ . '/subscriptions/xray/normal';
const SUBS_DIR_BASE64 = __DIR__ . '/subscriptions/xray/base64';

// NEW: Define the names for the fake configurations to be added
const FAKE_CONFIG_NAMES = [
    '#همکاری_ملی',
    '#جاویدشاه',
    '#KingRezaPahlavi'
];

// --- Helper Functions ---

/**
 * NEW: Creates a fake, non-functional VLESS config URI with a specific name.
 * These will be added to every subscription file.
 *
 * @param string $name The desired name for the config (e.g., '#MyFakeConfig').
 * @return string A VLESS URI string.
 */
function create_fake_config(string $name): string
{
    // The name should be URL encoded for the URI fragment part.
    $encodedName = urlencode(ltrim($name, '#'));
    // Create a non-functional VLESS config pointing to localhost.
    return "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:443?security=none&type=ws&path=/#{$encodedName}";
}

/**
 * Detects if the host in a config URI is an IPv4, IPv6, or a domain name.
 *
 * @param string $config The configuration URI.
 * @return string|null 'ipv4', 'ipv6', 'domain', or null if host is not found.
 */
function get_address_type(string $config): ?string
{
    $host = parse_url($config, PHP_URL_HOST);

    if (empty($host)) {
        return null;
    }

    // Trim brackets for IPv6 addresses like [::1]
    $ip = trim($host, '[]');

    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return 'ipv4';
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return 'ipv6';
    }
    // If it's not a valid IP, it's a domain name.
    return 'domain';
}

/**
 * NEW: Detects if a config uses HTTP header obfuscation (type=http).
 * This is common in VLESS and VMess.
 *
 * @param string $config The configuration URI.
 * @return bool True if the config has 'type=http', false otherwise.
 */
function is_xhttp(string $config): bool
{
    $queryString = parse_url($config, PHP_URL_QUERY);
    if (empty($queryString)) {
        return false;
    }

    parse_str($queryString, $params);

    return isset($params['type']) && $params['type'] === 'xhttp';
}


// --- 1. Load Input File ---

echo "1. Loading configurations from " . basename(CONFIG_FILE) . "..." . PHP_EOL;

if (!file_exists(CONFIG_FILE)) {
    die('Error: config.txt not found. Please run the previous scripts first.' . PHP_EOL);
}

$configsArray = file(CONFIG_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

if (empty($configsArray)) {
    die('Warning: config.txt is empty. No files will be generated.' . PHP_EOL);
}

echo "Loaded " . count($configsArray) . " configs." . PHP_EOL;


// --- 2. Sort Configurations into Groups ---

echo "2. Sorting configs by protocol and address type..." . PHP_EOL;

$sortedConfigs = [];

foreach ($configsArray as $config) {
    $trimmedConfig = trim($config);
    if (empty($trimmedConfig)) {
        continue;
    }

    $configType = detect_type($config);
    $addressType = get_address_type($config);

    if ($configType === null || $addressType === null) {
        continue;
    }

    // Add the config to its primary protocol group
    $sortedConfigs[$configType][$addressType][] = urldecode($config);

    // Add to special 'reality' group if applicable
    if ($configType === 'vless' && is_reality($config)) {
        $sortedConfigs['reality'][$addressType][] = urldecode($config);
    }

    // NEW: Add to special 'xhttp' group if applicable
    if (is_xhttp($config)) {
        $sortedConfigs['xhttp'][$addressType][] = urldecode($config);
    }
}

echo "Sorting complete. Found " . count($sortedConfigs) . " unique protocol/special types." . PHP_EOL;


// --- 3. Write Subscription Files ---

echo "3. Writing subscription files..." . PHP_EOL;

// NEW: Generate the list of fake config strings that will be appended to every file
$fakeConfigs = array_map('create_fake_config', FAKE_CONFIG_NAMES);

// NEW: Precheck - filter out configs that timeout before producing final files
require_once __DIR__ . '/scripts/precheck.php';

echo "4. Prechecking configs for timeouts (this may take some time)..." . PHP_EOL;
foreach ($sortedConfigs as $type => $addressGroups) {
    foreach ($addressGroups as $addressType => $configs) {
        $passed = precheck_config_list($configs, ['timeout' => 3, 'ports' => [443,80,53]]);
        // replace with passed-only
        $sortedConfigs[$type][$addressType] = $passed;
    }
}

if (!is_dir(SUBS_DIR_NORMAL)) {
    mkdir(SUBS_DIR_NORMAL, 0775, true);
}
if (!is_dir(SUBS_DIR_BASE64)) {
    mkdir(SUBS_DIR_BASE64, 0775, true);
}

$filesWritten = 0;
foreach ($sortedConfigs as $type => $addressGroups) {
    $allConfigsForType = [];

    // First, create the specific files (e.g., vless_ipv4, xhttp_domain)
    foreach ($addressGroups as $addressType => $configs) {
        $fileName = "{$type}_{$addressType}";
        $header = hiddifyHeader("PSG | " . strtoupper($type) . " " . strtoupper($addressType));
        
        // NEW: Merge real configs with the fake ones
        $contentWithFakes = array_merge($fakeConfigs, $configs);
        
        $plainTextContent = $header . implode(PHP_EOL, $contentWithFakes);
        $base64Content = base64_encode($plainTextContent);

        $normalFilePath = SUBS_DIR_NORMAL . '/' . $fileName;
        $base64FilePath = SUBS_DIR_BASE64 . '/' . $fileName;

        file_put_contents($normalFilePath, $plainTextContent);
        file_put_contents($base64FilePath, $base64Content);
        
        $filesWritten++;

        $allConfigsForType = array_merge($allConfigsForType, $configs);
    }

    // Second, create the main subscription for this type (e.g., vless, reality, xhttp)
    if (!empty($allConfigsForType)) {
        $fileName = $type;
        $header = hiddifyHeader("PSG | " . strtoupper($type));
        
        // NEW: Merge all configs for this type with the fake ones
        $allContentWithFakes = array_merge($fakeConfigs, $allConfigsForType);

        $plainTextContent = $header . implode(PHP_EOL, $allContentWithFakes);
        $base64Content = base64_encode($plainTextContent);
        
        $normalFilePath = SUBS_DIR_NORMAL . '/' . $fileName;
        $base64FilePath = SUBS_DIR_BASE64 . '/' . $fileName;

        file_put_contents($normalFilePath, $plainTextContent);
        file_put_contents($base64FilePath, $base64Content);
        
        $filesWritten++;
    }
}

echo "Done! Wrote {$filesWritten} total subscription files." . PHP_EOL;