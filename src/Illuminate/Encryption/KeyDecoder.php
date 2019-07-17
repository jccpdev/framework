<?php


namespace Illuminate\Encryption;


trait KeyDecoder
{
    public function decode($encodedKey)
    {
        $possibleDecoders = [
            'base64' => function ($encoded) {
                return base64_decode($encoded);
            },
        ];

        $splitValue = explode(":", $encodedKey);

        if (count($splitValue) < 2) {
            return null;
        }

        $decoder = $possibleDecoders[$splitValue[0]];

        if (empty($decoder)) {
            return null;
        }

        return $decoder($splitValue[1]);

    }
}