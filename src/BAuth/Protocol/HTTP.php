<?php

namespace BAuth\Protocol;

use BAuth;

class HTTP implements \BAuth\Protocol {
    protected $auth;
    protected $log;
    function __construct(\BAuth $auth, string $log = '') {
        $this->auth = $auth;
        $this->log = $log;
    }

    function authorize():int {
        if (empty($_SERVER['HTTP_AUTHORIZATION'])) { return BAuth::TOKEN_INVALID; }
        $authHeader = trim($_SERVER['HTTP_AUTHORIZATION']);

        if (substr($authHeader, 0, 6) !== 'Bearer') { return BAuth::TOKEN_INVALID; }
        $token = trim(substr($authHeader, 6));
       
        return $this->auth->checkToken($token);
    }

    function authenticate():string {
        if (empty($_SERVER['HTTP_AUTHORIZATION'])) { return ''; }
        $authHeader = trim($_SERVER['HTTP_AUTHORIZATION']);
        if (substr($authHeader, 0, 5) !== 'Basic') { return ''; }
        $authCredentials = base64_decode(trim(substr($authHeader, 5)));
        if (!$authCredentials) { return ''; }

        [$user, $password] = explode(':', $authCredentials, 2);
        return $this->auth->auth($user, $password);
    }

    function account():void {
        $log = $this->log;
        if (empty($log)) {
            $log = 'syslog';
        }
        $user = $this->auth->getCurrentUser();
        call_user_func($log, LOG_INFO, sprintf('USER <%s>, RESSOURCE <%s>, METHOD <%s>, SECURE <%s>, FROM <%s>, DATE <%s>',
            $user['user'],
            $_SERVER['REQUEST_URI'],
            $_SERVER['REQUEST_METHOD'],
            empty($_SERVER['HTTPS']) ? 'no' : 'yes',
            $_SERVER['REMOTE_ADDR'],
            (new \DateTime())->format('c')
        ));
    }
}