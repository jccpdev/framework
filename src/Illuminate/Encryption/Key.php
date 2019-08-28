<?php


namespace Illuminate\Encryption;


class Key
{

    /** @var string */
    private $id;

    /** @var string */
    private $value;

    /** @var string  */
    private $cipher;

    public function __construct($id, $value, $cipher = Cipher::AES_128_CBC)
    {
        $this->id = $id;
        $this->value = $value;
        $this->cipher = $cipher;
    }

    /**
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @param string $id
     * @return Key
     */
    public function setId($id)
    {
        $this->id = $id;
        return $this;
    }

    /**
     * @return string
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * @param string $value
     * @return Key
     */
    public function setValue($value)
    {
        $this->value = $value;
        return $this;
    }

    /**
     * @return string
     */
    public function getCipher()
    {
        return $this->cipher;
    }

    /**
     * @param string $cipher
     * @return Key
     */
    public function setCipher($cipher)
    {
        $this->cipher = $cipher;
        return $this;
    }

}
