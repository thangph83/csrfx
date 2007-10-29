<?php
/**
 * CSRFx
 * Requirements: PHP5
 *
 * Copyright (c) 2007 Mario Heiderich (http://php-ids.org)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * @package    CSRFx
 */

$config = new DATABASE_CONFIG();
$default = $config->default;
//$test = $config->test;
//$dev = $config->dev;

define('CSRFX_PATH', $default['driver'] . ':host=' . $default['host'] . ';dbname=' . $default['database']);
define('CSRFX_USER', $default['login']);
define('CSRFX_PASS', $default['password']);

/**
define('CSRFX_PATH', $test['driver'] . ':host=' . $test['host'] . ';dbname=' . $test['database']);
define('CSRFX_USER', $test['login']);
define('CSRFX_PASS', $test['password']); 

define('CSRFX_PATH', $dev['driver'] . ':host=' . $dev['host'] . ';dbname=' . $dev['database']);
define('CSRFX_USER', $dev['login']);
define('CSRFX_PASS', $dev['password']);
**/ 