<?php
require_once __DIR__ . '/../src/utils/helpers.php';
session_destroy();
redirect('login.php');
