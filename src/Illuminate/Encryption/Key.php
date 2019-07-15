<?php


namespace Illuminate\Encryption;


class Key
{

    private $id;

    private $value;

    private $cipher;

    public function __construct($id, $value, $cipher = Cipher::AES_128_CBC)
    {
        $this->id = $id;
        $this->value = $value;
        $this->cipher = $cipher;
    }

    /**
     * @return mixed
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @param mixed $id
     * @return Key
     */
    public function setId($id)
    {
        $this->id = $id;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * @param mixed $value
     * @return Key
     */
    public function setValue($value)
    {
        $this->value = $value;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getCipher()
    {
        return $this->cipher;
    }

    /**
     * @param mixed $cipher
     * @return Key
     */
    public function setCipher($cipher)
    {
        $this->cipher = $cipher;
        return $this;
    }


}