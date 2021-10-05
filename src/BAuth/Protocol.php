<?php
namespace BAuth;

interface Protocol {
    function authorize():int;
    function authenticate():string;
    function account():void;
}