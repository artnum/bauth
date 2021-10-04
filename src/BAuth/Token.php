<?php

namespace BAuth;

interface Token {
    public function setToken(string $user, string $token):bool;
    public function getToken(string $token):array;
    public function delToken(string $token):void;
}