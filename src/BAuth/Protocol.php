<?php
namespace BAuth;

interface Protocol {
    function authorize():bool;
    function authenticate():string;
    function account():void;
}