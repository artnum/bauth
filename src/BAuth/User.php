<?php

namespace BAuth;

interface User {
    public function setPassword(string $user, string $password, string $halgo, string $salt, int $iterations):bool;
    public function getPassword(string $user):array;
}