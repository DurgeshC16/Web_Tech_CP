<?php
// public/dev_mailbox.php — LOCAL DEVELOPMENT ONLY.
// Lists the emails the app saved to private_data/mail/ (MAIL_TRANSPORT=file),
// so verification codes can be read without a real mail account.
// Hard-disabled (404) in production, for non-loopback visitors, and whenever
// real mail delivery is configured.
require_once __DIR__ . '/../src/config/config.php';

$ip = $_SERVER['REMOTE_ADDR'] ?? '';
$local = in_array($ip, ['127.0.0.1', '::1'], true);
if (getenv('CV_ENV') === 'production' || !$local || MAIL_TRANSPORT !== 'file') {
    http_response_code(404);
    exit('Not found');
}

header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: no-store');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'");

$dir = __DIR__ . '/../private_data/mail';
$files = is_dir($dir) ? glob($dir . '/*.eml') : [];
rsort($files);
$files = array_slice($files, 0, 20);
?>
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta http-equiv="refresh" content="10">
<title>Dev mailbox</title>
<style>
body{font:15px system-ui,sans-serif;max-width:760px;margin:24px auto;padding:0 16px;background:#f4f6fb;color:#15213b}
.m{background:#fff;border:1px solid #d9dee5;border-radius:10px;padding:14px 16px;margin:12px 0}
.c{font:700 28px ui-monospace,monospace;letter-spacing:.2em;color:#4338ca}
small{color:#5b6472}
</style></head><body>
<h1>Dev mailbox</h1>
<p><small>Local only. Newest first, refreshes every 10 s. Codes expire after 10 minutes.</small></p>
<?php if (!$files): ?><p>No emails yet.</p><?php endif; ?>
<?php foreach ($files as $f):
    $raw = (string)file_get_contents($f);
    preg_match('/^To: (.*)$/m', $raw, $to);
    preg_match('/^Subject: (.*)$/m', $raw, $sub);
    preg_match('/^Date: (.*)$/m', $raw, $dt);
    $body = trim(preg_replace('/^.*?\R\R/s', '', $raw, 1));
    $body = preg_replace('~<(style|script|head)\b.*?</\1>~is', ' ', $body);
    $text = trim(html_entity_decode(strip_tags(preg_replace("~<[^>]+>~", " ", $body))));
    $code = (preg_match('/:\s*(\d{6})\s/u', $text, $cm) || preg_match('/(?<![#\w])(\d{6})(?!\w)/', $text, $cm)) ? $cm[1] : '';
?>
<div class="m">
  <strong><?= htmlspecialchars($sub[1] ?? '') ?></strong><br>
  <small>To <?= htmlspecialchars($to[1] ?? '') ?> · <?= htmlspecialchars($dt[1] ?? '') ?></small>
  <?php if ($code !== ''): ?><div class="c"><?= htmlspecialchars($code) ?></div><?php endif; ?>
</div>
<?php endforeach; ?>
</body></html>
