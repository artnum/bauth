<?php

namespace BAuth\TStore;

use Exception;

class File implements \BAuth\Token {
    protected $base;

    function __construct($base) {
        if (!is_dir($base) || !is_writable($base)) {
            throw new Exception('Directory path not a directory or not writable');
        }
        $this->base = $base;
    }

    function mkpath (string $token):string {
        $dir1 = substr($token, 0, 2);
        $dir2 = substr($token, 2, 2);

        if (!is_dir("$this->base/$dir1")) {
            if (!@mkdir("$this->base/$dir1")) {
                return '';
            }
        }

        if (!is_dir("$this->base/$dir1/$dir2")) {
            if (!@mkdir("$this->base/$dir1/$dir2")) {
                return '';
            }
        }

        return "$this->base/$dir1/$dir2/$token";
    }

    function setToken (string $user, string $token):bool {
        $object = [
            'user' => $user,
            'date' => (new \DateTime('now'))->format('c')
        ];
        $path = $this->mkpath($token);
        if (empty($path)) { return false; }
        if (is_file($path)) { return false; }
        if (!file_put_contents($path, json_encode($object))) {
            return false;
        }

        return true;
    }

    function getToken(string $token):array {
        $path = $this->mkpath($token);
        if (empty($path)) { return []; }
        $content = file_get_contents($path);
        if (!$content) { return []; }
        $object = json_decode($content, true);
        if (!$object) { return false; }
        $object['date'] = new \DateTime($object['date']);
        return $object;
    }

    function delToken(string $token):void {
        $path = $this->mkpath($token);
        if (empty($path)) { return; }
        @unlink($path);
        return;
    }
}