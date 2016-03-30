![http://php-ids.org/files/csrfx_logo.png](http://php-ids.org/files/csrfx_logo.png)


This library attempts to create an easy way to mitigate CSRF attacks on PHP5 based web applications.

The application basically has to be included via the php.ini/VHost settings auto\_prepend\_file and auto\_append\_file. The tool will utilize a small application settings file to connect to the applications database and check for all forms and links matching a certain pattern. Those will will be extended with a one time token.

You need PHP5 - but not a specific database wrapper anymore. The application configuration files allow you to use the application specific wrapper or generic ones like PDO or mysqli. Currently packed is an example application file for CakePHP.