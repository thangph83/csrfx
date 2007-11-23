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
 * PHP version 5.11.6+
 * 
 * @category Security
 * @package  CSRFx
 * @author   Mario Heiderich <mario.heiderich@gmail.com>
 * @license  http://www.gnu.org/licenses/lgpl.html LGPL
 * @link     http://code.google.com/p/csrfx/
 */

//instanciate databse config object
$config  = new DATABASE_CONFIG();
$default = $config->default;

//define config parameters
define('CSRFX_EXCLUDE', '/(?:\/admin\/)/i');
define('CSRFX_USER', $default['login']);
define('CSRFX_PASS', $default['password']);
define('CSRFX_PATH', $default['driver'] . 
                     ':host=' . $default['host'] . 
                     ';dbname=' . $default['database']);


//fetch cake session for better scalability
$session       = new CakeSession;
$session       = $session->read();
$this->session = session_id();

//fetch the cake connection manager
$this->dbh =& ConnectionManager::getDataSource('default');
$this->dbm = 'query';

$this->get_patterns = array('/\/whatever/i',
                            '/\/you/i', 
                            '/\/want/i');

$this->post_patterns = array('/\/whatever/i',
                            '/\/you/i', 
                            '/\/want/i');