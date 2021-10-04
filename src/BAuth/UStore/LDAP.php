<?php

namespace BAuth\UStore;

class LDAP implements \BAuth\User {
    protected $conn;
    protected $base;

    function __construct($ldapConn, string $base) {
        $this->conn = $ldapConn;
        $this->base = $base;
    }

    function setPassword(string $user, string $password, string $halgo, string $salt, int $iterations):bool {
        $res = @ldap_search(
            $this->conn,
            $this->base,
            '(name=' . ldap_escape($user, '', LDAP_ESCAPE_FILTER) . ')',
            [ 'name', 'userPassword', 'bauthIterations', 'bauthSalt', 'bauthAlgo', 'bauthCreated']
        );

        if (!$res) { return false; }
        $entryCount = @ldap_count_entries($this->conn, $res);
        echo $entryCount;
        if ($entryCount > 1 || $entryCount < 1) { return false; }
        $entry = @ldap_first_entry($this->conn, $res);
        if (!$entry) { return false; }

        $map = [
            'bauthIterations' => $iterations,
            'bauthSalt' => $salt,
            'bauthAlgo' => $halgo,
            'bauthCreated' => (new \DateTime())->getTimestamp() 
        ];

        /* single-value, so it either exists and we replace or we add */
        foreach([
            'bauthIterations',
            'bauthSalt',
            'bauthAlgo',
            'bauthCreated'
        ] as $attr) {
            $values = @ldap_get_values($this->conn, $entry, $attr);
            if (!$values || $values['count'] === 0) {
                $mods[] = [
                    'attrib' => $attr,
                    'modtype' => LDAP_MODIFY_BATCH_ADD,
                    'values' => [$map[$attr]]
                ];
                continue;
            }

            $mods[] = [
                'attrib' => $attr,
                'modtype' => LDAP_MODIFY_BATCH_REPLACE,
                'values' => [$map[$attr]]
            ];
        }

        /* password can come from several source */
        $userPassVal = @ldap_get_values($this->conn, $entry, 'userPassword');
        $userPass = false;
        if ($userPassVal && $userPassVal['count'] > 0) {
            $pass = [];
            for($i = 0; $i < $userPassVal['count']; $i++) {
                if (substr($userPassVal[$i], 0, 7) !== '{BAUTH}') { $pass[] = $userPassVal[$i]; continue; }
                $pass[] = '{BAUTH}' . $password;
                $userPass = true;
            }
            if ($userPass) {
                $mods[] = [
                    'attrib' => 'userPassword',
                    'modtype' => LDAP_MODIFY_BATCH_REPLACE,
                    'values' => $pass
                ];
            }
        }
        if (!$userPass) {
            /* bauthPassword is single-value */
            $values = ldap_get_values($this->conn, $entry, 'bauthPassword');
            if ($values && $values['count'] > 0) {
                $mods[] = [
                    'attrib' => 'bauthPassword',
                    'modtype' => LDAP_MODIFY_BATCH_REPLACE,
                    'values' => ['{BAUTH}' . $password]
                ];
            } else {
                $mods[] = [
                    'attrib' => 'bauthPassword',
                    'modtype' => LDAP_MODIFY_BATCH_ADD,
                    'values' => ['{BAUTH}' . $password]
                ];
            }
        }

        return ldap_modify_batch($this->conn, ldap_get_dn($this->conn, $entry), $mods);
    }

    function getPassword(string $user):array {
        $res = @ldap_search(
            $this->conn,
            $this->base,
            '(name=' . ldap_escape($user, '', LDAP_ESCAPE_FILTER) . ')',
            [ 'name', 'userPassword', 'bauthIterations', 'bauthSalt', 'bauthAlgo', 'bauthCreated']
        );

        if (!$res) { return []; }
        $entryCount = @ldap_count_entries($this->conn, $res);
        if ($entryCount > 1 || $entryCount < 1) { return []; }
        $entry = @ldap_first_entry($this->conn, $res);
        if (!$entry) { return []; }

        $object = [
            'username' => '',
            'password' => '',
            'iterations' => 0,
            'salt' => '',
            'created' => 0,
            'algo' => ''
        ];
        for ($attr = ldap_first_attribute($this->conn, $entry); $attr; $attr = ldap_next_attribute($this->conn, $entry)) {
            $values = ldap_get_values($this->conn, $entry, $attr);
            if ($values['count'] < 1) { continue; }
            switch ($attr) {
                default:
                    /* name can be any of cn,sn,... just compare value and set */
                    for ($i = 0; $i < $values['count']; $i++) {
                        if (hash_equals($values[$i], $user)) {
                            $object['username'] = $values[$i];
                        }
                    }
                    break;
                case 'userPassword':
                case 'bauthPassword':
                    for ($i = 0; $i < $values['count']; $i++) {
                        if (substr($values[$i], 0, 7) !== '{BAUTH}') { continue; }
                        $object['password'] = substr($values[$i], 7);
                    }
                    break;
                case 'bauthCreated':
                    $object['created'] = intval($values[0]);
                    break;
                case 'bauthIterations':
                    $object['iterations'] = intval($values[0]);
                    break;
                case 'bauthSalt':
                    $object['salt'] = $values[0];
                    break;
                case 'bauthAlgo':
                    $object['algo'] = $values[0];
                    break;
            }
        }
        if (empty($object['username'])) { return []; }
        return $object;
    }
}