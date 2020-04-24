<?php

namespace HttpSignatures\Tests;

use PHPUnit\Framework\TestCase as _TestCase;

abstract class TestCase extends _TestCase {
    public static function unix_line_endings($old) {
        return preg_replace('/\r\n?/', "\n", $old);
    }
}