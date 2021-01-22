<?php
namespace UrlEncoder;
/**
 * UrlEncoder
 * Classe de cryptage principalement pour crypter des données à transmettre en paramètre d'url,
 * s'appuie sur le module mcrypt de php
 * 
 * $encoder = new UrlEncoder(array(
 *			'key' => 'lkaqlkj lkj%;dflsdjflsdsjfdlsdfsd ff65468ze', // la longueur dépend de l'algo utilisé
 *			'iv' => 'zezolnsdlflknsdf*ùkn', // la longueur dépend de l'algo utilisé
 *			'algorithm' => 'rijndael-256',
 *		));
 *	$params = array(
 *		date('YmdHis'), // timestamp
 *		'1ère donnée',
 *		'2nde donnée',
 *	);
 *	$ticket = $encoder->encode($params);
 *	$url = 'http://....?ticket='.$ticket;
 * 
 * et pour décoder:  
 * $params = $encoder->decode($ticket);
 * 
 * 
 * @author Thomas Parodi - Scarabe
 * @version 1.0
 * @license MIT
 * 
 */
class UrlEncoder {
	// grain de Sel
	private $iv = '1234567890123456789012345678901234567890';
	// clé privée
	private $key = '1234567890123456789012345678901234567890';
	// algorithme de cryptage (correspondant aux algorithmes disponibles de mcrypt )
	private $algorithm = 'blowfish';

	private $mode = OPENSSL_RAW_DATA;

	private $no_mcrypt = false;

    /**
     * Mode de cryptage
     *
     * config => array(
     *        'key' => 'lkaqlkj lkj%;dflsdjflsdsjfdlsdfsd ff65468ze', // la longueur dépend de l'algo utilisé
     *        'iv' => 'zezolnsdlflknsdf*ùkn', // la longueur dépend de l'algo utilisé
     *        'algorithm' => 'rijndael-256',
     *    )
     *
     * @param object $config
     * @throws Exception
     */
	public function __construct($config){
		if (isset($config['algorithm']) && !empty($config['algorithm'])){
			$algorithms = openssl_get_cipher_methods();
			if (!in_array($config['algorithm'], $algorithms)){
				//throw new Exception('Algorithme de cryptage incorrect: '.$config['algorithm']);
			}
			$this->algorithm = $config['algorithm'];
		}
//			throw new Exception('La librairie MCRYPT n\'est pas installée.');
		if (isset($config['iv']) && !empty($config['iv'])){
			$this->setIv($config['iv']);
		}
		if (isset($config['key']) && !empty($config['key'])){
			$this->setKey($config['key']);
		}
	}
	
	public function setKey($key){
		$this->key = $key;
	}

	public function setIv($iv){
		$this->iv = $iv;
	}

	/**
	 * cryptage de texte
	 * 
	 * @param object $text
	 * @return string
	 */
	public function crypt($text){
		return str_replace(
			array('/', '=', '+'),
			array('-','_','$'),
			base64_encode(openssl_encrypt($text, $this->algorithm, $this->key, $this->mode, $this->iv))
		);
	}

	/**
	 * décryptage de texte
	 * 
	 * @param object $text
	 * @return string
	 */
	public function decrypt($text){
			return openssl_decrypt(base64_decode(str_replace(
				array('-','_','$'),
				array('/', '=', '+'),
				$text
			)), $this->algorithm, $this->key, $this->mode, $this->iv);
	}

    /**
     * cryptage de texte/tableau/objet (la variable est d'abord encodée json)
     *
     * @param object|array|string $params
     * @return string
     */
	public function encode($params){
		return $this->crypt(json_encode($params));
	}

    /**
     * décryptage de texte/tableau/objet (la variable est d'abord décodée json)
     *
     * @param object|string $text
     * @param bool $assoc
     * @return mixed
     */
	public function decode($text, $assoc = true){
		return json_decode(trim($this->decrypt($text)), $assoc);
	}
	
}