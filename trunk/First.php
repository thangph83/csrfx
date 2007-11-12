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

// needed sql:  CREATE TABLE `csrfx_tokens` (`id` VARCHAR( 255 ) NOT NULL ,`session` VARCHAR( 255 ) NOT NULL, `agent` VARCHAR( 255 ) NOT NULL ,`created` TIMESTAMP NOT NULL) ENGINE = MYISAM 
// optional sql: ALTER TABLE `csrfx_tokens` ADD INDEX ( `id` )
// optional sql: ALTER TABLE `csrfx_tokens` ADD INDEX ( `session` ) 

/**
 * This class inhabits all necessary 
 * logic for CSRFx
 *
 * @package CSRFx
 * @var private the name of the request parameter
 * @var private the token to protect forms and links - has to be null!
 * @var private the patterns for the requests to protect
 * @var private the application to load a config for - null if you have an own config 
 * @var private the database handle
 */
class CSRFX {
    
    private $name = 't';
    private $separator = '?';
    private $token = false;
    private $method = false;
    private $browser = false;
    
    private $get_patterns = false;
    private $post_patterns = false;    
    
    private $session = false;
    private $dbh = false;
    private $dbm = false;
    
    /**
     * The constructor makes sure the session has been started, 
     * generates the token and starts output buffering
     *
     * @package CSRFx
     * @param void
     * @return boolean true
     */
    public function __construct() {
        
        $this->method = strtolower($_SERVER['REQUEST_METHOD']);
        $this->browser = isset($_SERVER['HTTP_USER_AGENT'])?md5($_SERVER['HTTP_USER_AGENT']):md5(microtime()*rand(1,10));
        
        ob_start();
        $this->token = sha1(microtime()*rand());
        
        return true;
    }

    /**
     * This method loads the applications profile file in which databse 
     * connection data and patterns can be found
     *
     * @package CSRFx
     * @param string the applications name/name of the profile file
     * @throws Exception
     * @return Object this object for pagination
     */
    public function loadProfile($name = false) {
        if ($name && !preg_match('/\W/', $name)) {
            require_once dirname(__FILE__) . '/applications/' . 
                escapeshellcmd($name) .'.php';
        } else {
            throw new Exception ('Invalid application name format');
        }
        
        return $this;
    }
    
    /**
     * This method checks either for request method and the request uri. 
     * If a method besides POST and GET is requested the application will 
     * stop with 405 headers sent.  
     * 
     * This method has to be called before any application 
     * logic was evaluated.
     *
     * @package CSRFx
     * @param void
     * @throws Exception
     */
    public function beginProtection() {
        #disable support for XHR //TODO: think about a solution
        if($this->isAjax()) {
            return false;
        }

        #and clear the table from before adding new token
        $this->deleteTokens();        
        
        if($this->method == 'get' || $this->method == 'post') {
            foreach ($this->{$this->method . '_patterns'} as $pattern) {
                if(preg_match($pattern, rawurldecode($_SERVER['REQUEST_URI'])) 
                  || isset($_POST[$this->name])) {
                    #check get requests
                    if (preg_match('/=(\w{40})$/', rawurldecode($_SERVER['REQUEST_URI']), $matches)) {
                        $result = $this->fetchToken($this->session, $this->browser);
                        if (!$result || !in_array($matches[1], $result, true)) {
                            $this->evokePenalty();		                	
                        } 
                    }
                    #check post requests
                    elseif (isset($_POST[$this->name])) {
                        $result = $this->fetchToken($this->session, $this->browser);
                        if (!$result || !in_array($_POST[$this->name], $result, true)) {
                            $this->evokePenalty();                          
                        }
                    } 
                    #no token found - penalty time!
                    else {
                        $this->evokePenalty();
                    }
                }
            }
        } else {
            #method not allowed
            header('HTTP/1.1 405 Method Not Allowed');
            throw new Exception('HTTP/1.1 405 Method Not Allowed');
        }
        return true;
    }
    
    /**
     * This method modified the markup of the application, ends the output 
     * buffering and writes the next token to the database.
     * 
     * This method has to be called after the last application logic 
     * was evaluated.
     * 
     * @package CSRFx
     * @param void
     * @return boolean 
     */
    public function endProtection() {
        #disable support for XHR //TODO: think about a solution 
        if($this->isAjax()) {
            return false;
        }
        
        $this->output = ob_get_contents();
        ob_end_clean();
        
        #add token to matching links 
        $matches = array();
        preg_match_all('/(?:href="([^"\']+)")/i', $this->output, $matches);
        foreach(array_unique($matches[1]) as $link) {
            foreach ($this->{$this->method . '_patterns'} as $pattern) {
                if (preg_match($pattern, substr($link, 0, -1))){
                    $this->output = str_ireplace($link, $link.$this->separator.$this->name.'='.$this->token, $this->output);            
                }
            }
        }

        #add token to forms
        $this->output = str_ireplace('</form>', '<input type="hidden" name="'.$this->name.'" value="'.$this->token.'" /></form>', $this->output);            
        
        #add new token to table
        $this->addToken();

        #finally print the output
        print $this->output;
        
        return true;
    }

    /**
     * This method sets the 412 headers and redirects 
     * to the index page of the application.
     *
     * @package CSRFx
     * @param void
     * @return void
     */
    private function evokePenalty($message = false) {
        header('location: /sicherheitsproblem/');
        exit;
    }

    /**
     * This method deletes the tokens with the matching CSRFX_SESSION
     *
     * @package CSRFx
     * @param void
     * @return boolean true
     */
    private function deleteTokens() {
        $this->dbh->{$this->dbm}("DELETE FROM csrfx_tokens WHERE created < DATE_SUB(NOW(), INTERVAL 30 MINUTE)");
        return true;
    }
    
    /**
     * This method returns the result set for the token query
     *
     * @package CSRFx
     * @param string the token to look for
     * @return mixed the result array or false
     */
    private function fetchToken($session = false, $browser = false) {
        $result = $this->dbh->{$this->dbm}("SELECT id FROM csrfx_tokens 
                                               WHERE session = '".mysql_escape_string($session)."'
                                               AND agent = '".mysql_escape_string($browser)."'");
        
        if($result) {
            $tokens = array();
            foreach($result as $item) {
                $tokens[] = $item['csrfx_tokens']['id'];
            }
            return $tokens;
        }
        return false;
    }
    
    /**
     * This method adds a new token to the crsfx table
     * 
     * @package CSRFx
     * @param void
     * @return mixed the execution result 
     */
    private function addToken() {
        return $this->dbh->{$this->dbm}("INSERT 
                                            INTO csrfx_tokens (id, session, agent, created) 
                                            VALUES (
                                                '".mysql_escape_string($this->token)."', 
                                                '".mysql_escape_string($this->session)."', 
                                                '".mysql_escape_string(md5($_SERVER['HTTP_USER_AGENT']))."', 
                                                NOW()
                                             )
                                         ");
    }
    
    /**
     * This method checks if the request was XHR and returns 
     * a true if yes
     * 
     * @package CSRFx
     * @param void
     * @return boolean true if XHR
     */
    private function isAjax() {
        if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) 
            && $_SERVER['HTTP_X_REQUESTED_WITH'] == 'XMLHttpRequest'
                || preg_match(CSRFX_EXCLUDE, $_SERVER['REQUEST_URI'])) {
            return true;
        }
        return false;     	
    }
}    

#create instance and start protection
$csrf = new CSRFX();
$csrf->loadProfile('cakephp')->beginProtection();