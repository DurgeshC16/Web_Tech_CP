<?php
// tests/fixtures/config_probe.php
// Loads config.php and prints a marker. Used by test_config_guard.php to
// observe whether the production guard allows the process to continue.
require __DIR__ . '/../../src/config/config.php';
echo "CV_CONFIG_LOADED\n";
