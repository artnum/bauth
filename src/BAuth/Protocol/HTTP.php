<?php

namespace BAuth\Protocol;

use BAuth;

class HTTP implements \BAuth\Protocol {
    protected $auth;
    protected $log;
    function __construct(\BAuth $auth, string $log = '') {
        $this->auth = $auth;
        $this->log = empty($log) ? 'syslog' : $log;
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
        $user = $this->auth->getCurrentUser();
        call_user_func($this->log, LOG_INFO, sprintf('USER <%s>, RESSOURCE <%s>, METHOD <%s>, SECURE <%s>, FROM <%s>, DATE <%s>',
            $user['user'],
            $_SERVER['REQUEST_URI'],
            $_SERVER['REQUEST_METHOD'],
            empty($_SERVER['HTTPS']) ? 'no' : 'yes',
            $_SERVER['REMOTE_ADDR'],
            (new \DateTime())->format('c')
        ));
    }

    function run(string $realm):int {
        $authStatus = $this->authorize();
        switch ($authStatus) {
            case BAuth::TOKEN_OK:
                $this->account();
                return BAuth\Protocol::AUTH_OK;
            case BAuth::TOKEN_EXPIRED:
                $error = [
                    'error' => 'invalid_client',
                    'error_description' => 'Authentication expired'
                ];
            case BAuth::TOKEN_INVALID:
                $error['error_description'] = 'Authentication invalid';
                $tk = $this->authenticate();
                header('Content-Type: application/json');
                header('Cache-Control: no-cache');
                header('Pragma: no-cache');
                if (empty($tk)) {
                    http_response_code(401);
                    header('WWW-Authenticate: Basic realm="' . $realm . '"');
                    echo json_encode($error);
                    return BAuth\Protocol::AUTH_INVALID;
                }
                echo json_encode(['access_token' => $tk, 'token_type' => 'bearer', 'expires_in' => $this->auth->getTokenMaxTime()]);
                return BAuth\Protocol::AUTH_DONE;
        }
    }
}