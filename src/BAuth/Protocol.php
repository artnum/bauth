<?php
namespace BAuth;

interface Protocol {
    const AUTH_INVALID  = 0; 
    const AUTH_OK       = 1;
    const AUTH_DONE     = 2;
    function authorize():int;
    function authenticate():string;
    function account():void;
    function run(string $realm):int;
}