<?php

declare(strict_types=1);

// --- Setup ---
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

// Ensure the helper functions and ConfigWrapper class are available
require_once __DIR__ . '/functions.php';
if (!class_exists('ConfigWrapper')) { die('Error: ConfigWrapper class not found in functions.php'); }

// --- Configuration Constants ---
const INPUT_DIR = __DIR__ . '/subscriptions/xray/base64';
const OUTPUT_DIR_BASE = __DIR__ . '/subscriptions';
const TEMPLATES_DIR = __DIR__ . '/templates';
const GITHUB_BASE_URL = 'https://raw.githubusercontent.com/yasi-python/PSG/main';

const ALLOWED_SS_METHODS = ["chacha20-ietf-poly1305", "aes-256-gcm"];
// Define which input files can be converted to which output formats
const OUTPUT_MAPPING = [
    'clash' => ['mix', 'vmess', 'vmess_ipv4', 'vmess_ipv6', 'vmess_domain', 'trojan', 'trojan_ipv4', 'trojan_ipv6', 'trojan_domain', 'ss', 'ss_ipv4', 'ss_ipv6', 'ss_domain'],
    'meta' => ['mix', 'vmess', 'vmess_ipv4', 'vmess_ipv6', 'vmess_domain', 'vless', 'vless_ipv4', 'vless_ipv6', 'vless_domain', 'reality', 'reality_ipv4', 'reality_ipv6', 'reality_domain', 'trojan', 'trojan_ipv4', 'trojan_ipv6', 'trojan_domain', 'ss', 'ss_ipv4', 'ss_ipv6', 'ss_domain'],
    'surfboard' => ['mix', 'vmess', 'vmess_ipv4', 'vmess_ipv6', 'vmess_domain', 'trojan', 'trojan_ipv4', 'trojan_ipv6', 'trojan_domain', 'ss', 'ss_ipv4', 'ss_ipv6', 'ss_domain'],
];

// #############################################################################
// Universal Data Converters (Input -> Generic PHP Array)
// #############################################################################

function vmessToProxyData(ConfigWrapper $c): ?array {
    if (!is_valid_uuid($c->getUuid())) return null;
    $proxy = [
        "name" => $c->getTag(), "type" => "vmess", "server" => $c->getServer(), "port" => $c->getPort(),
        "cipher" => ($c->get('scy') ?: 'auto'), "uuid" => $c->getUuid(), "alterId" => $c->get('aid', 0),
        "tls" => $c->get('tls') === 'tls', "skip-cert-verify" => true, "network" => $c->get('net', 'tcp'),
    ];
    if ($proxy['network'] === "ws") {
        $proxy["ws-opts"] = ["path" => $c->getPath(), "headers" => ["Host" => $c->get('host', $c->getServer())]];
    } elseif ($proxy['network'] === "grpc") {
        $proxy["grpc-opts"] = ["grpc-service-name" => $c->getServiceName(), "grpc-mode" => $c->get('type')];
        $proxy["tls"] = true;
    }
    return $proxy;
}

function vlessToProxyData(ConfigWrapper $c): ?array {
    if (!is_valid_uuid($c->getUuid())) return null;
    $proxy = [
        "name" => $c->getTag(), "type" => "vless", "server" => $c->getServer(), "port" => $c->getPort(),
        "uuid" => $c->getUuid(), "tls" => $c->getParam('security') === 'tls' || $c->getParam('security') === 'reality',
        "network" => $c->getParam('type', 'tcp'), "client-fingerprint" => "chrome", "udp" => true,
    ];
    if ($c->getParam('sni')) $proxy["servername"] = $c->getParam('sni');
    if ($c->getParam('flow')) $proxy["flow"] = 'xtls-rprx-vision';
    if ($proxy['network'] === "ws") {
        $proxy["ws-opts"] = ["path" => $c->getPath(), "headers" => ["Host" => $c->getParam('host', $c->getServer())]];
    } elseif ($proxy['network'] === "grpc" && $c->getParam('serviceName')) {
        $proxy["grpc-opts"] = ["grpc-service-name" => $c->getParam('serviceName')];
    }
    if ($c->getParam('security') === 'reality') {
        if (in_array(strtolower($c->getParam('fp', '')), ["android", "ios", "random"])) return null;
        $proxy["client-fingerprint"] = $c->getParam('fp');
        $proxy["reality-opts"] = ["public-key" => $c->getParam('pbk')];
        if ($c->getParam('sid')) $proxy["reality-opts"]["short-id"] = $c->getParam('sid');
    }
    return $proxy;
}

function trojanToProxyData(ConfigWrapper $c): ?array {
    return [
        "name" => $c->getTag(), "type" => "trojan", "server" => $c->getServer(), "port" => $c->getPort(),
        "password" => $c->getPassword(), "skip-cert-verify" => (bool)$c->getParam("allowInsecure", false),
    ];
}

function ssToProxyData(ConfigWrapper $c): ?array {
    $method = $c->get('encryption_method');
    if (!in_array($method, ALLOWED_SS_METHODS)) return null;
    return [
        "name" => $c->getTag(), "type" => "ss", "server" => $c->getServer(), "port" => $c->getPort(),
        "password" => $c->getPassword(), "cipher" => $method,
    ];
}

// #############################################################################
// Profile Generator Classes
// #############################################################################

abstract class ProfileGenerator {
    protected array $proxies = [];
    protected array $proxyNames = [];
    public function addProxy(array $proxyData): void {
        $formattedProxy = $this->formatProxy($proxyData);
        if ($formattedProxy) {
            $this->proxies[] = $formattedProxy;
            $this->proxyNames[] = $proxyData['name'];
        }
    }
    abstract protected function formatProxy(array $proxyData): ?string;
    abstract public function generate(): string;
}

class ClashProfile extends ProfileGenerator {
    private string $type; // 'clash' or 'meta'
    public function __construct(string $type) { $this->type = $type; }
    
    protected function formatProxy(array $proxyData): ?string {
        // Standard Clash doesn't support VLESS or REALITY. Filter them out.
        if ($this->type === 'clash') {
            if ($proxyData['type'] === 'vless') return null;
            if (isset($proxyData['reality-opts'])) return null;
        }
        // CORRECTED: Added "- " to format as a YAML list item.
        return '  - ' . json_encode($proxyData, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    public function generate(): string {
        $template = file_get_contents(TEMPLATES_DIR . '/clash.yaml');
        
        $proxies_yaml = implode("\n", $this->proxies);
        
        // Correctly format the list of proxy names with proper indentation
        $proxy_names_yaml = '';
        foreach ($this->proxyNames as $name) {
            $proxy_names_yaml .= "      - '" . str_replace("'", "''", $name) . "'\n";
        }
        $proxy_names_yaml = rtrim($proxy_names_yaml); // Remove last newline

        // Replace placeholders
        $final_yaml = str_replace('##PROXIES##', $proxies_yaml, $template);
        $final_yaml = str_replace('##PROXY_NAMES##', $proxy_names_yaml, $final_yaml);
        
        return $final_yaml;
    }
}

class SurfboardProfile extends ProfileGenerator {
    private string $configUrl;
    public function __construct(string $configUrl) { $this->configUrl = $configUrl; }
    
    protected function formatProxy(array $proxyData): ?string {
        $type = $proxyData['type'];
        // Surfboard doesn't support VLESS or newer SS ciphers
        if ($type === 'vless' || ($type === 'ss' && $proxyData['cipher'] === '2022-blake3-aes-256-gcm')) return null;

        $name = str_replace(',', ' ', $proxyData['name']); // Commas are delimiters
        $parts = ["{$name} = {$type}", $proxyData['server'], $proxyData['port']];
        
        if ($type === 'vmess') {
            $parts[] = "username = " . $proxyData['uuid'];
            $parts[] = "ws = " . ($proxyData['network'] === 'ws' ? 'true' : 'false');
            $parts[] = "tls = " . ($proxyData['tls'] ? 'true' : 'false');
            if ($proxyData['network'] === 'ws') {
                $parts[] = "ws-path = " . $proxyData['ws-opts']['path'];
                $parts[] = 'ws-headers = Host:"' . $proxyData['ws-opts']['headers']['Host'] . '"';
            }
        } elseif ($type === 'trojan') {
            $parts[] = "password = " . $proxyData['password'];
            $parts[] = "skip-cert-verify = " . ($proxyData['skip-cert-verify'] ? 'true' : 'false');
            if (isset($proxyData['servername'])) $parts[] = "sni = " . $proxyData['servername'];
        } elseif ($type === 'ss') {
            $parts[] = "encrypt-method = " . $proxyData['cipher'];
            $parts[] = "password = " . $proxyData['password'];
        }
        return implode(", ", $parts);
    }
    
    public function generate(): string {
        $template = file_get_contents(TEMPLATES_DIR . '/surfboard.ini');
        $proxies_ini = implode("\n", $this->proxies);
        $proxy_names_ini = implode(", ", array_map(fn($name) => str_replace(',', ' ', $name), $this->proxyNames));
        
        $final_ini = str_replace('##CONFIG_URL##', $this->configUrl, $template);
        $final_ini = str_replace('##PROXIES##', $proxies_ini, $final_ini);
        return str_replace('##PROXY_NAMES##', $proxy_names_ini, $final_ini);
    }
}

// --- Main Script Execution ---

echo "Starting subscription conversions..." . PHP_EOL;

$files_to_process = glob(INPUT_DIR . '/*');

foreach ($files_to_process as $filepath) {
    $inputType = pathinfo($filepath, PATHINFO_FILENAME);
    echo "Processing input file: {$inputType}..." . PHP_EOL;
    
    $base64_data = file_get_contents($filepath);
    $configs = file(sprintf('data:text/plain;base64,%s', $base64_data), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    
    if (empty($configs)) {
        echo "  -> Skipping {$inputType}, no configs found." . PHP_EOL;
        continue;
    }
    
    // Convert all configs to a neutral format once
    $proxyDataList = [];
    foreach ($configs as $config_str) {
        $wrapper = new ConfigWrapper($config_str);
        if (!$wrapper->isValid()) continue;
        
        $proxyData = match($wrapper->getType()) {
            'vmess' => vmessToProxyData($wrapper),
            'vless' => vlessToProxyData($wrapper),
            'trojan' => trojanToProxyData($wrapper),
            'ss' => ssToProxyData($wrapper),
            default => null
        };
        if ($proxyData) $proxyDataList[] = $proxyData;
    }

    // Now, generate all required output files from the neutral data
    foreach (OUTPUT_MAPPING as $outputType => $allowedInputs) {
        if (in_array($inputType, $allowedInputs)) {
            echo "  -> Generating {$outputType} profile..." . PHP_EOL;
            
            $outputDir = OUTPUT_DIR_BASE . '/' . $outputType;
            if (!is_dir($outputDir)) mkdir($outputDir, 0775, true);

            $generator = match($outputType) {
                'clash', 'meta' => new ClashProfile($outputType),
                'surfboard' => new SurfboardProfile(GITHUB_BASE_URL . '/subscriptions/surfboard/' . $inputType),
                default => null
            };
            if (!$generator) continue;

            foreach($proxyDataList as $proxyData) {
                $generator->addProxy($proxyData);
            }
            
            file_put_contents($outputDir . '/' . $inputType, $generator->generate());
        }
    }
}

echo "All conversions are complete!" . PHP_EOL;
