<?php
/**
 * Plugin Name: Application Passwords v2
 * Plugin URI: https://github.com/Zmimmy/application-passwords-v2
 * Description: A prototype framework to add application passwords to core.
 * Author: George Stephanis 
 * Version: 0.1-dev
 */

/**
 * Include the application passwords system.
 */
require_once( dirname( __FILE__ ) . '/class.application-passwords.php' );
Application_Passwords::add_hooks();
