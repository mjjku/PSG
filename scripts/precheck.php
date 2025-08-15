<?php
declare(strict_types=1);

require_once __DIR__ . '/../functions.php';

/**
 * Lightweight pre-checker for proxy configs.
 * - Tests connectivity (TCP by default) to the server/port found in each config.
 * - Removes configs that timeout or fail.
 * - Can optionally use external tools (nping/hping3) when available.
 *
 * Designed to be conservative and rate-limited to reduce ban risk.
 */

// Safe mode: when SKIP_NETWORK_PROBES is set to "1" in the environment (useful for
// running on GitHub Actions or other CI systems), the precheck functions will
// skip any external network probes and return the input configs after basic
// trimming. This avoids running active network scans from ephemeral runners.
define('SKIP_NETWORK_PROBES', getenv('SKIP_NETWORK_PROBES') === '1');

function find_executable(string $name): ?string
{
    $which = trim((string)shell_exec('which ' . escapeshellarg($name) . ' 2>/dev/null'));
    return $which === '' ? null : $which;
}

function test_endpoint_tcp(string $host, int $port, float $timeoutSeconds = 3.0): ?float
{
    $start = microtime(true);
    $errno = 0;
    $errstr = '';
    // Suppress warnings from fsockopen and rely on return value
    $fp = @fsockopen($host, $port, $errno, $errstr, (float)$timeoutSeconds);
    $rtt = null;
    if ($fp !== false) {
        stream_set_blocking($fp, 0);
        $rtt = (microtime(true) - $start) * 1000.0; // ms
        fclose($fp);
    }
    return $rtt; // null means failed
}

function test_endpoint_icmp(string $host, int $timeoutSeconds = 3): ?float
{
    // Use system ping (conservative). Returns RTT in ms or null.
    $pingBin = find_executable('ping');
    if ($pingBin === null) return null;
    $cmd = escapeshellcmd($pingBin) . ' -c 1 -W ' . intval($timeoutSeconds) . ' ' . escapeshellarg($host) . ' 2>&1';
    $out = shell_exec($cmd);
    if ($out === null) return null;
    if (preg_match('/time=([0-9\.]+) ms/', $out, $m)) {
        return (float)$m[1];
    }
    return null;
}

function run_nping_probe(string $nping, string $host, int $port, string $proto = 'tcp', int $timeout = 3): ?float
{
    // Example nping usage: nping --tcp -p 443 --count 1 --delay 1s --tcp-connect
    $protoFlag = '';
    $extra = '';
    if ($proto === 'tcp') {
        $protoFlag = '--tcp';
    } elseif ($proto === 'udp') {
        $protoFlag = '--udp';
    } elseif ($proto === 'icmp') {
        $protoFlag = '--icmp';
    }
    $cmd = escapeshellarg($nping) . ' ' . $protoFlag . ' -p ' . intval($port) . ' --count 1 --tcp-connect --data-length 0 --delay 1s ' . escapeshellarg($host) . ' 2>&1';
    $out = shell_exec($cmd);
    if ($out === null) return null;
    if (preg_match('/rtt=?\s*=?([0-9\.]+)ms/i', $out, $m)) {
        return (float)$m[1];
    }
    if (preg_match('/Avg rtt:\s*([0-9\.]+)ms/i', $out, $m)) {
        return (float)$m[1];
    }
    return null;
}

/**
 * Determine host/port candidates for a config string using existing parser helpers.
 */
function extract_host_port_from_config(string $config): array
{
    $type = detect_type($config);
    $parsed = configParse($config);
    if ($parsed === null) return [];

    switch ($type) {
        case 'vmess':
            // configParse returns decoded array for vmess
            return [trim($parsed['add'] ?? ''), intval($parsed['port'] ?? 0)];
        case 'vless':
        case 'trojan':
        case 'tuic':
        case 'hy2':
            return [trim($parsed['hostname'] ?? $parsed['server_address'] ?? ''), intval($parsed['port'] ?? $parsed['server_port'] ?? 0)];
        case 'ss':
            return [trim($parsed['server_address'] ?? ''), intval($parsed['server_port'] ?? 0)];
        default:
            return [];
    }
}

/**
 * Precheck a list of config strings (plain text array). Returns only passing configs.
 * Options:
 *  - timeout: seconds
 *  - ports: array of fallback ports
 *  - replace: whether to overwrite original file (used by file helper)
 */
function precheck_config_list(array $configs, array $options = []): array
{
    if (SKIP_NETWORK_PROBES) {
        // Minimal sanitization in safe mode: trim and remove empty lines.
        echo "[SAFE-MODE] SKIP_NETWORK_PROBES=1 — skipping network probes\n";
        $trimmed = array_values(array_filter(array_map('trim', $configs), fn($v) => $v !== ''));
        return $trimmed;
    }

    $timeout = $options['timeout'] ?? 3;
    $portsFallback = $options['ports'] ?? [443, 80, 53];
    $minDelay = $options['min_delay'] ?? 0.5;
    $maxDelay = $options['max_delay'] ?? 1.5;
    $useNping = find_executable('nping');

    $passed = [];
    $total = count($configs);
    $i = 0;
    foreach ($configs as $config) {
        $i++;
        $cfg = trim($config);
        if ($cfg === '') continue;

        $hostPort = extract_host_port_from_config($cfg);
        if (empty($hostPort) || empty($hostPort[0])) {
            // No host found: drop this config
            echo "[SKIP] No host found for config {$i}/{$total}\n";
            continue;
        }
        $host = $hostPort[0];
        $port = (int)$hostPort[1];

        $portsToTry = [];
        if ($port > 0) $portsToTry[] = $port;
        foreach ($portsFallback as $p) {
            if (!in_array($p, $portsToTry, true)) $portsToTry[] = $p;
        }

        $ok = false;
        foreach ($portsToTry as $p) {
            // Try nping when available (prefer precise RTT)
            if ($useNping) {
                $rtt = run_nping_probe($useNping, $host, $p, 'tcp', (int)$timeout);
                if ($rtt !== null) { $ok = true; break; }
            }
            $rtt = test_endpoint_tcp($host, $p, (float)$timeout);
            if ($rtt !== null) { $ok = true; break; }
            // Try ICMP as a last resort
            $rtt = test_endpoint_icmp($host, (int)$timeout);
            if ($rtt !== null) { $ok = true; break; }
        }

        if ($ok) {
            $passed[] = $cfg;
            echo "[OK] {$host}: passed ({$i}/{$total})\n";
        } else {
            echo "[TIMEOUT] {$host}: removing ({$i}/{$total})\n";
        }

        // Rate limit and random delay to reduce detection
        usleep((int)(1000000 * ($minDelay + lcg_value() * ($maxDelay - $minDelay))));
    }

    return $passed;
}

function precheck_file_configs(string $filePath, array $options = []): array
{
    if (!file_exists($filePath)) return [];
    $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $passed = precheck_config_list($lines, $options);
    if (!empty($options['replace']) && $options['replace'] === true) {
        file_put_contents($filePath, implode(PHP_EOL, $passed) . PHP_EOL);
    }
    return $passed;
}

function precheck_base64_string(string $base64data, array $options = []): string
{
    $lines = preg_split('/\R/', base64_decode($base64data));
    $lines = array_filter(array_map('trim', $lines));
    $passed = precheck_config_list($lines, $options);
    return base64_encode(implode(PHP_EOL, $passed));
}
