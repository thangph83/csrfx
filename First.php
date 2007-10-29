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

// needed sql:  CREATE TABLE `csrf_tokens` (`token` VARCHAR( 255 ) NOT NULL ,`session` VARCHAR( 255 ) NOT NULL ,`created` TIMESTAMP NOT NULL) ENGINE = MYISAM 
// optional sql: ALTER TABLE `csrf_tokens` ADD INDEX ( `token` )
// optional sql: ALTER TABLE `csrf_tokens` ADD INDEX ( `session` ) 

/**
 * This nclass inhabits all necessary 
 * logic for CSRFX
 *
 * @var private the name of the request parameter
 * @var private the token to protect forms and links - has to be null!
 * @var private the patterns for the requests to protect
 * @var private the application to load a config for - null if you have an own config 
 * @var private the database handle
 */
class CSRFX {
    
    private $name = '?schutz-token=';
    private $token = null;
    private $patterns = array('/\/admin\//i', 
                              '/\/anlegen\//i', 
                              '/\/loeschen\//i', 
                              '/\/bearbeiten\//i',
                              '/\/logout\//i');
    
    private $application = 'cakephp'; // cakephp | wordpress | null
    private $dbh = null;
    
    /**
     * Enter description here...
     *
     */
    public function __construct() {
        
        ob_start();
        $this->token = sha1(microtime()*rand());
        
        if(!session_id()) {
        	session_start();
        }

        if(!is_null($this->application)) {
            require_once dirname(__FILE__) . '/applications/' . 
                escapeshellcmd($this->application) .'.php';
            
            $this->dbh = new PDO(CSRFX_PATH, CSRFX_USER, CSRFX_PASS);
        } else {
            die('no config given');
        }        
        
        return true;
    }
    
    /**
     * Enter description here...
     *
     */
    public function beginProtection() {

        if($_SERVER['REQUEST_METHOD'] == 'GET' || $_SERVER['REQUEST_METHOD'] == 'POST') {
            foreach($this->patterns as $pattern) {
                if(preg_match($pattern, $_SERVER['REQUEST_URI'])) {
                	if(preg_match('/'.str_replace('?', '\?', $this->name).'(\w{40})/', $_SERVER['REQUEST_URI'], $matches)) {
	                	$statement = $this->dbh->prepare("SELECT * FROM csrf_tokens WHERE token = ?");
	                    $statement->execute(array($matches[1]));
	                    $result = $statement->fetch();
						if(!$result || $result['session'] != session_id()) {
	                        die('Possible CSRF Attack detected');		                	
						} 
                	}
                }
            }
            
            $statement = $this->dbh->prepare("DELETE FROM csrf_tokens WHERE session = ?");
            $statement->execute(array(session_id()));               
            
        } else {
        	header('HTTP/1.1 405 Method Not Allowed');
            die();
        }
        
        return true;
    }
    
    /**
     * Enter description here...
     *
     */
    public function endProtection() {
        
        $this->output = ob_get_contents();
        ob_end_clean();
        
        $matches = array();
        preg_match_all('/(?:href="([^"]+))/i', $this->output, $matches);
        foreach($matches[1] as $link) {
            foreach($this->patterns as $pattern) {
                if(preg_match($pattern, $link)){
                    $this->output = str_ireplace($link, $link . $this->name . $this->token, $this->output);            
                }
            }
        }
        
        print $this->output;
        
        $statement = $this->dbh->prepare("INSERT INTO csrf_tokens (token, session, created) VALUES (:token, :session, NOW())");
        $statement->bindParam(':token', $this->token);
        $statement->bindParam(':session', session_id());
        $statement->execute();        
        
        return true;
    }
}

        
$csrf = new CSRFX();
$csrf->beginProtection();