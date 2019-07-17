<?php


namespace Illuminate\Contracts\Encryption;


use Illuminate\Contracts\Config\Repository;
use Illuminate\Encryption\KeyStore;

interface KeyStoreFactory
{
    public function make(Repository $config): KeyStore;
}