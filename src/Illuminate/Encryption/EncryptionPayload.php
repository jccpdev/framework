<?php


namespace Illuminate\Encryption;


class EncryptionPayload implements \JsonSerializable
{

    private $iv;

    private $value;

    private $mac;

    private $keyId;

    public function __construct($iv, $value, $mac, $keyId)
    {
        $this->iv = $iv;
        $this->value = $value;
        $this->mac = $mac;
        $this->keyId = $keyId;
    }

    /**
     * @return mixed
     */
    public function getIv()
    {
        return $this->iv;
    }

    /**
     * @return mixed
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * @return mixed
     */
    public function getMac()
    {
        return $this->mac;
    }

    /**
     * @return mixed
     */
    public function getKeyId()
    {
        return $this->keyId;
    }

    /**
     * Specify data which should be serialized to JSON
     * @link https://php.net/manual/en/jsonserializable.jsonserialize.php
     * @return mixed data which can be serialized by <b>json_encode</b>,
     * which is a value of any type other than a resource.
     * @since 5.4.0
     */
    public function jsonSerialize()
    {
        return [
            'iv'    => $this->iv,
            'value' => $this->value,
            'mac'   => $this->mac,
            'keyId' => $this->keyId,
        ];
    }
}