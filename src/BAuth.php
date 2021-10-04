<?php

class BAuth {
    protected $ustore;
    protected $tstore;
    const SALT_LENGTH = 32;
    const ITERATIONS = 50000;

    function __construct (BAuth\User $ustore, BAuth\Token $tstore) {
        $this->ustore = $ustore;   
        $this->tstore = $tstore;
        $this->algo = '';
    }

    function gen_token (string $user, string $password):string {
        $date = (new DateTime('now'))->format('c');
        $random = bin2hex(random_bytes(32));
        $token = hash_hmac('sha256', "$date$random$user", hash_pbkdf2('sha1', $password, random_bytes(16), 500, 0, false));

        if (!$this->tstore->setToken($user, $token)) {
            return '';
        }

        return $token;
    }

    function checkToken (string $user, string $token):bool {
        $object = $this->tstore->getToken($token);
        if ((new DateTime())->getTimestamp() - $object['date']->getTimestamp() > 1500000) {
            $this->tstore->delToken($token);
            return false;
        }
        if (!hash_equals($object['user'], $user)) {
            return false;
        }
        return true;
    }

    function auth (string $user, string $password):string {
        $sPassword = $this->ustore->getPassword($user);
        if (empty($sPassword)) { return ''; }

        $hashList = hash_algos();
        if (array_search($sPassword['algo'], $hashList) === false) { return ''; }

        $derived = hash_pbkdf2($sPassword['algo'], $password, $sPassword['salt'], $sPassword['iterations']);
        if (!hash_equals($sPassword['password'], $derived)) { return ''; }

        return $this->gen_token($user, $password);
    }

    function passwd (string $user, string $password):bool {
        $hash = '';
        $hashList = hash_algos();
        foreach (['sha3-512', 'sha512', 'sha3-156', 'sha256', 'sha1', 'md5'] as $probableHash) {
            if (array_search($probableHash, $hashList) !== false) {
                $hash = $probableHash;
                break;
            }
        }
        if (empty($hash)) { throw new Exception('No hash algo found'); }
        $salt = random_bytes(self::SALT_LENGTH);
        $derived = hash_pbkdf2($hash, $password, $salt, self::ITERATIONS, 0, false);
        return $this->ustore->setPassword($user, $derived, $hash, $salt, self::ITERATIONS);
    }
}