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

/*
 * SQL
 * 
 * necessary sql:  CREATE TABLE `csrfx_tokens` (`id` VARCHAR( 255 ) NOT NULL ,
 *      `session` VARCHAR( 255 ) NOT NULL, 
 *      `agent` VARCHAR( 255 ) NOT NULL ,
 *      `created` TIMESTAMP NOT NULL) ENGINE = MYISAM 
 *
 * optional sql: ALTER TABLE `csrfx_tokens` ADD INDEX ( `id` )
 * optional sql: ALTER TABLE `csrfx_tokens` ADD INDEX ( `session` ) 
 * 
 */


/**
 * This class inhabits all necessary 
 * logic for CSRFx
 *
 * @category Security
 * @package  CSRFx
 * @author   Mario Heiderich <mario.heiderich@gmail.com>
 * @license  http://www.gnu.org/licenses/lgpl.html LGPL
 * @link     http://code.google.com/p/csrfx/
 * @var      private the name of the request parameter
 * @var      private the token to protect forms and links - has to be null!
 * @var      private the patterns for the requests to protect
 * @var      private the application to load a config for - null for own config 
 * @var      private the database handle
 */
class CSRFX
{
    
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
    
    private $penalty_url = '/security-problem/'; 
    
    /**
     * The constructor makes sure the session has been started, 
     * generates the token and starts output buffering
     *
     * @package CSRFx
     * @return boolean true
     */
    public function __construct() 
    {
        
        $this->method  = strtolower($_SERVER['REQUEST_METHOD']);
        $this->browser = isset($_SERVER['HTTP_USER_AGENT'])
            ?md5($_SERVER['HTTP_USER_AGENT']):md5(microtime()*rand(1, 10));
        
        ob_start();
        $this->token = sha1(microtime()*rand());
        
        return true;
    }

    /**
     * This method loads the applications profile file in which databse 
     * connection data and patterns can be found
     *
     * @package CSRFx
     * @param string $name The application name
     * 
     * @throws Exception if invaild application name is given
     * @return Object this object for pagination
     */
    public function loadProfile($name = false) 
    {
        if ($name && !preg_match('/\W/', $name)) {
            include_once dirname(__FILE__) . '/applications/' . 
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
     * @throws Exception if method is not get or post
     * @return void
     */
    public function beginProtection() 
    {
        //disable support for XHR //TODO: think about a solution
        if ($this->_isAjax()) {
            return false;
        }

        //and clear the table from before adding new token
        $this->_deleteTokens();        
        
        if ($this->method == 'get' || $this->method == 'post') {
            foreach ($this->{$this->method . '_patterns'} as $pattern) {
                if (preg_match($pattern, rawurldecode($_SERVER['REQUEST_URI'])) 
                  || isset($_POST[$this->name])) {
                    if (preg_match('/=(\w{40})$/', 
                        rawurldecode($_SERVER['REQUEST_URI']), $matches)) {
                        $result = $this->_fetchToken($this->session, $this->browser);
                        if (!$result || !in_array($matches[1], $result, true)) {
                            $this->_evokePenalty();		                	
                        } 
                    } elseif (isset($_POST[$this->name])) {
                        $result = $this->_fetchToken($this->session, 
                            $this->browser);
                        if (!$result || !in_array($_POST[$this->name], 
                            $result, true)) {
                            $this->_evokePenalty();                          
                        }
                    } else {
                        $this->_evokePenalty();
                    }
                }
            }
        } else {
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
     * @return boolean 
     */
    public function endProtection()
    {
        //disable support for XHR //TODO: think about a solution 
        if ($this->_isAjax()) {
            return false;
        }
        
        $this->output = ob_get_contents();
        ob_end_clean();
        
        //add token to matching links
        preg_match('/(([\w-]+\.)?[\w-]+$)/', $_SERVER['HTTP_HOST'], $host); 
        preg_match_all('/(?:<a href=\'([^\']+)\'>)|(?:<a href="([^"]+)">)|' . 
            '(?:<a href=`([^`]+)`>)|(?:<a href=\s*([^\s]+)\s>)/im', 
            $this->output, $matches);
        $matches = array_unique(array_merge($matches[1], $matches[2], 
            $matches[3], $matches[4])); 
        foreach ($matches as $link) {
            preg_match('/([\w-]+\.[\w-]+)\//', $link, $submatches);
            if (!isset($submatches[1]) || $submatches[1] == $host[1]) {
                foreach ($this->{$this->method . '_patterns'} as $pattern) {
                    if (preg_match($pattern, substr($link, 0, -1))) {
                        $this->output = str_ireplace($link, 
                        $link.$this->separator.$this->name.'='.$this->token, 
                        $this->output);            
                    }
                }
            }
        }

        //add token to forms
        $this->output = str_ireplace('</form>', '<input type="hidden" name="'.
            $this->name.'" value="'.$this->token.'" /></form>', $this->output);
        $this->output = preg_replace('/(action="[^\"]+\/)\?t=\w{40}\"/', "$1\"",
            $this->output);
         
        //add new token to table
        $this->_addToken();

        //finally print the output
        print $this->output;
        
        return true;
    }

    /**
     * This method sets the 412 headers and redirects 
     * to the index page of the application.
     *
     * @package CSRFx
     * @return void
     */
    private function _evokePenalty() 
    {
        header('location: '.$this->penalty_url);
        exit;
    }

    /**
     * This method deletes the tokens with the matching CSRFX_SESSION
     *
     * @package CSRFx
     * @return boolean true
     */
    private function _deleteTokens() 
    {
        $this->dbh->{$this->dbm}("DELETE FROM csrfx_tokens WHERE created " . 
            "< DATE_SUB(NOW(), INTERVAL 30 MINUTE)");
        return true;
    }
    
    /**
     * This method returns the result set for the token query
     *
     * @package CSRFx
     * @param string $session The session id
     * @param string $browser The browser hash
     * 
     * @return mixed the result array or false
     */
    private function _fetchToken($session = false, $browser = false) 
    {
        $result = $this->dbh->{$this->dbm}("SELECT id FROM csrfx_tokens 
                                            WHERE session = '".
                                            mysql_escape_string($session)."'
                                            AND agent = '".
                                            mysql_escape_string($browser)."'");
        
        if ($result) {
            $tokens = array();
            foreach ($result as $item) {
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
     * @return mixed the execution result 
     */
    private function _addToken() 
    {
        return $this->
            dbh->{$this->dbm}("INSERT 
                              INTO csrfx_tokens (id, session, agent, created) 
                              VALUES (
                              '".mysql_escape_string($this->token)."', 
                              '".mysql_escape_string($this->session)."', 
                              '".mysql_escape_string($this->browser)."', 
                              NOW()
                              )");
    }
    
    /**
     * This method checks if the request was XHR and returns 
     * a true if yes
     * 
     * @package CSRFx
     * @return boolean true if XHR
     */
    private function _isAjax() 
    {
        if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) 
            && $_SERVER['HTTP_X_REQUESTED_WITH'] == 'XMLHttpRequest'
                || preg_match(CSRFX_EXCLUDE, $_SERVER['REQUEST_URI'])) {
            return true;
        }
        return false;     	
    }
}    

//create instance and start protection
$csrf = new CSRFX();
$csrf->loadProfile('cakephp')->beginProtection();