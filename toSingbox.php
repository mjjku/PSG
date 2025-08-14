<?php

declare(strict_types=1);

/**
 * This script converts various proxy subscription formats (VLESS, VMess, etc.)
 * into multiple JSON configuration formats (sing-box, nekobox). It processes 
 * multiple input files and generates corresponding profiles for each format.
 */

// --- Setup ---
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

require_once __DIR__ . '/functions.php';

// --- Configuration Constants ---
const INPUT_DIR = __DIR__ . '/subscriptions/xray/base64';

// NEW: Define an array of conversion tasks. This makes adding more formats in the future easy.
const CONVERSION_TASKS = [
    'sing-box' => [
        'output_dir' => __DIR__ . '/subscriptions/singbox',
        'structure_file' => __DIR__ . '/templates/structure.json',
        'include_header' => true
    ],
    'nekobox' => [
        'output_dir' => __DIR__ . '/subscriptions/nekobox',
        'structure_file' => __DIR__ . '/templates/nekobox.json',
        'include_header' => false
    ],
];

const ALLOWED_SS_METHODS = [
    "chacha20-ietf-poly1305",
    "aes-256-gcm",
    "2022-blake3-aes-256-gcm"
];

// #############################################################################
// Refactored Conversion Functions
// #############################################################################

// --- These functions remain unchanged as they convert the individual proxy URLs, ---
// --- which is a common step for both sing-box and nekobox. ---

function vmessToSingbox(ConfigWrapper $c): ?array
{
    $config = [
        "tag" => $c->getTag(), "type" => "vmess", "server" => $c->getServer(),
        "server_port" => $c->getPort(), "uuid" => $c->getUuid(), "security" => "auto",
        "alter_id" => (int)$c->get('aid'),
    ];
    if ($c->getPort() === 443 || $c->get('tls') === 'tls') {
        $config["tls"] = createTlsSettings($c);
    }
    if (in_array($c->getTransportType(), ["ws", "grpc", "http"])) {
        $config["transport"] = createTransportSettings($c);
        if ($config["transport"] === null) return null; // Invalid transport
    }
    return $config;
}

function vlessToSingbox(ConfigWrapper $c): ?array
{
    $config = [
        "tag" => $c->getTag(), "type" => "vless", "server" => $c->getServer(),
        "server_port" => $c->getPort(), "uuid" => $c->getUuid(),
        "flow" => $c->getParam('flow') ? "xtls-rprx-vision" : "", "packet_encoding" => "xudp",
    ];
    if ($c->getPort() === 443 || in_array($c->getParam('security'), ['tls', 'reality'])) {
        $config["tls"] = createTlsSettings($c);
        if ($c->getParam('security') === 'reality' || $c->getParam('pbk')) {
            $config['flow'] = "xtls-rprx-vision";
            $config["tls"]["reality"] = ['enabled' => true, 'public_key' => $c->getParam('pbk', ''), 'short_id' => $c->getParam('sid', '')];
            $config["tls"]["utls"]['fingerprint'] = $c->getParam('fp');
            if (empty($config["tls"]["reality"]['public_key'])) return null;
        }
    }
    if (in_array($c->getTransportType(), ["ws", "grpc", "http"])) {
        $config["transport"] = createTransportSettings($c);
        if ($config["transport"] === null) return null;
    }
    return $config;
}

function trojanToSingbox(ConfigWrapper $c): ?array
{
    $config = [
        "tag" => $c->getTag(), "type" => "trojan", "server" => $c->getServer(),
        "server_port" => $c->getPort(), "password" => $c->getPassword(),
    ];
    if ($c->getPort() === 443 || $c->getParam('security') === 'tls') {
        $config["tls"] = createTlsSettings($c);
    }
    if (in_array($c->getTransportType(), ["ws", "grpc", "http"])) {
        $config["transport"] = createTransportSettings($c);
        if ($config["transport"] === null) return null;
    }
    return $config;
}

function ssToSingbox(ConfigWrapper $c): ?array
{
    $method = $c->get('encryption_method');
    if (!in_array($method, ALLOWED_SS_METHODS)) {
        return null;
    }
    return [
        "tag" => $c->getTag(), "type" => "shadowsocks", "server" => $c->getServer(),
        "server_port" => $c->getPort(), "method" => $method, "password" => $c->getPassword(),
    ];
}

function tuicToSingbox(ConfigWrapper $c): ?array
{
    return [
        "tag" => $c->getTag(), "type" => "tuic", "server" => $c->getServer(),
        "server_port" => $c->getPort(), "uuid" => $c->getUuid(), "password" => $c->getPassword(),
        "congestion_control" => $c->getParam("congestion_control", "bbr"),
        "udp_relay_mode" => $c->getParam("udp_relay_mode", "native"),
        "tls" => [
            "enabled" => true,
            "server_name" => $c->getSni(),
            "insecure" => (bool)$c->getParam("allow_insecure", 0),
            "alpn" => empty($c->getParam('alpn')) ? null : explode(',', $c->getParam('alpn')),
        ]
    ];
}

function hy2ToSingbox(ConfigWrapper $c): ?array
{
    $obfsPass = $c->getParam('obfs-password');
    if (empty($obfsPass)) return null;

    return [
        "tag" => $c->getTag(), "type" => "hysteria2", "server" => $c->getServer(),
        "server_port" => $c->getPort(), "password" => $c->getPassword(),
        "obfs" => ["type" => $c->getParam('obfs'), "password" => $obfsPass],
        "tls" => [
            "enabled" => true,
            "server_name" => $c->getSni(),
            "insecure" => (bool)$c->getParam("insecure", 0),
            "alpn" => ["h3"],
        ],
    ];
}

// #############################################################################
// Unified Helper Functions
// #############################################################################

function createTlsSettings(ConfigWrapper $c): array
{
    return [
        "enabled" => true, "server_name" => $c->getSni(), "insecure" => true,
        "utls" => ["enabled" => true, "fingerprint" => "chrome"],
    ];
}

function createTransportSettings(ConfigWrapper $c): ?array
{
    $transportType = $c->getTransportType();
    $transport = match($transportType) {
        'ws' => ["type" => "ws", "path" => $c->getPath(), "headers" => ["Host" => $c->getSni()]],
        'grpc' => ["type" => "grpc", "service_name" => $c->getServiceName()],
        'http' => ["type" => "http", "host" => [$c->getSni()], "path" => $c->getPath()],
        default => null
    };
    // Centralized validation
    if ($transportType === 'grpc' && empty($transport['service_name'])) {
        return null;
    }
    return $transport;
}

// #############################################################################
// Main Processing Logic
// #############################################################################

/**
 * Main router function to convert any config string to a sing-box array.
 */
function convert_to_config_array(string $config_string): ?array // MODIFIED: Renamed for clarity
{
    $wrapper = new ConfigWrapper($config_string);
    if (!$wrapper->isValid()) {
        return null;
    }
    // MODIFIED: Renamed function calls, but the logic is identical.
    return match($wrapper->getType()) {
        "vmess" => vmessToSingbox($wrapper),
        "vless" => vlessToSingbox($wrapper),
        "trojan" => trojanToSingbox($wrapper),
        "ss" => ssToSingbox($wrapper),
        "tuic" => tuicToSingbox($wrapper),
        "hy2" => hy2ToSingbox($wrapper),
        default => null,
    };
}

/**
 * Generates the full profile JSON from a list of configs and a base structure.
 */
function generate_profile(string $base64_configs, array $base_structure, string $profile_name, bool $include_header): string
{
    $configs = file(sprintf('data:text/plain;base64,%s', $base64_configs), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    
    foreach ($configs as $config) {
        $outboundConfig = convert_to_config_array($config);
        if ($outboundConfig !== null) {
            $base_structure['outbounds'][] = $outboundConfig;
            $tag = $outboundConfig['tag'];

            if (isset($base_structure['outbounds'][0]['outbounds']) && is_array($base_structure['outbounds'][0]['outbounds'])) {
                 $base_structure['outbounds'][0]['outbounds'][] = $tag;
            }
            if (isset($base_structure['outbounds'][1]['outbounds']) && is_array($base_structure['outbounds'][1]['outbounds'])) {
                $base_structure['outbounds'][1]['outbounds'][] = $tag;
            }
        }
    }

    $final_output = '';

    // MODIFIED: Conditionally generate and prepend the header
    if ($include_header) {
        $base64Name = base64_encode($profile_name);
        $header = <<<HEADER
//profile-title: base64:{$base64Name}
//profile-update-interval: 1
//subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531
//support-url: https://t.me/yebekhe
//profile-web-page-url: ithub.com/yasi-python/PSG

HEADER;
        $final_output .= $header;
    }

    $final_output .= json_encode($base_structure, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

    return $final_output;
}


// --- Script Execution ---

// MODIFIED: The entire execution block is refactored to loop through the tasks.

// **ROBUSTNESS**: Use glob to find all input files once.
$files_to_process = glob(INPUT_DIR . '/*');
if (empty($files_to_process)) {
    echo "No files found in " . INPUT_DIR . " to process." . PHP_EOL;
    exit;
}

// Loop through each conversion task (sing-box, nekobox, etc.)
foreach (CONVERSION_TASKS as $task_name => $task_config) {
    echo "#####################################################" . PHP_EOL;
    echo "Starting conversion to {$task_name} format..." . PHP_EOL;

    $output_dir = $task_config['output_dir'];
    $structure_file = $task_config['structure_file'];

    if (!file_exists($structure_file)) {
        echo "Error: Structure file '{$structure_file}' for {$task_name} not found. Skipping." . PHP_EOL;
        continue; // Skip to the next task
    }
    
    // Read the base structure for the current task
    $base_structure = json_decode(file_get_contents($structure_file), true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        echo "Error: Invalid JSON in '{$structure_file}'. Skipping {$task_name}." . PHP_EOL;
        continue; // Skip to the next task
    }

    // Ensure the output directory for the current task exists
    if (!is_dir($output_dir)) {
        mkdir($output_dir, 0775, true);
    }
    
    // Process all input files for the current task
    foreach ($files_to_process as $filepath) {
        $filename = pathinfo($filepath, PATHINFO_FILENAME);
        $profile_name = "PSG | " . strtoupper($filename);
        
        echo "  -> Processing {$filename} for {$task_name}..." . PHP_EOL;

        $base64_data = file_get_contents($filepath);

        // We need a fresh copy of the structure for each file, so we re-assign it.
        $structure_for_this_file = $base_structure;
        
        $converted_profile = generate_profile($base64_data, $structure_for_this_file, $profile_name, $task_config['include_header']);
        
        file_put_contents($output_dir . '/' . $filename . ".json", $converted_profile);
    }

    echo "Conversion to {$task_name} complete!" . PHP_EOL;
}

echo "#####################################################" . PHP_EOL;
echo "All tasks finished." . PHP_EOL;
