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
	private $algorithm = 'rijndael-256';
	// mode de cryptage
	private $mode = MCRYPT_MODE_ECB;

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
		$this->no_mcrypt = !function_exists('mcrypt_encrypt');
		if(isset($config['force_no_mcrypt']) && $config['force_no_mcrypt']){
			$this->no_mcrypt = true;
		}
		if (!$this->no_mcrypt){
			if (isset($config['algorithm']) && !empty($config['algorithm'])){
				$algorithms = mcrypt_list_algorithms();
				if (!in_array($config['algorithm'], $algorithms)){
					throw new Exception('Algorithme de cryptage incorrect: '.$config['algorithm']);
				}
				$this->algorithm = $config['algorithm'];
			}
			if (isset($config['mode']) && !empty($config['mode'])){
				$modes = mcrypt_list_modes();
				if (!in_array($config['mode'], $modes)){
					throw new Exception('Mode de cryptage incorrect: '.$config['mode']);
				}
				$this->mode = $config['mode'];
			}
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
		if (!$this->no_mcrypt){
		    $key_size = mcrypt_get_key_size($this->algorithm, $this->mode);
			if (strlen($key) > $key_size){
				$key = substr($key, 0, $key_size);
			}
		}
		$this->key = $key;
	}

	public function setIv($iv){
		if (!$this->no_mcrypt){
		    $iv_size = mcrypt_get_iv_size($this->algorithm, $this->mode);
			if (strlen($iv) > $iv_size){
				$iv = substr($iv, 0, $iv_size);
			}
		}
		$this->iv = $iv;
	}
	/**
	 * cryptage de texte
	 * 
	 * @param object $text
	 * @return string
	 */
	public function crypt($text){
		if (!$this->no_mcrypt){
			return str_replace(
				array('/', '=', '+'),
				array('-','_','$'),
				base64_encode(mcrypt_encrypt($this->algorithm, $this->key, $text, $this->mode, $this->iv))
			);
		}
		return $this->_no_mcrypt_crypt($text);
	}
	/**
	 * décryptage de texte
	 * 
	 * @param object $text
	 * @return string
	 */
	public function decrypt($text){
		if (!$this->no_mcrypt){
			return mcrypt_decrypt($this->algorithm, $this->key, base64_decode(str_replace(
				array('-','_','$'),
				array('/', '=', '+'),
				$text
			)), $this->mode, $this->iv);
		}
		return $this->_no_mcrypt_decrypt($text);
	}
	function _no_mcrypt_decrypt($text){
		$key = md5($this->key);
		$letter = -1;
		$newstr = '';
		$text = base64_decode($text);
		$strlen = strlen($text);
		for ( $i = 0; $i < $strlen; $i++ ){
			$letter++;
			if ( $letter > 31 ){
				$letter = 0;
			}
			$neword = ord($text{$i}) - ord($key{$letter});
			if ( $neword < 1 ){
				$neword += 256;
			}
			$newstr .= chr($neword);
		}
		return $newstr;
	}
	
	function _no_mcrypt_crypt($text){
		$key = md5($this->key);
		$letter = -1;
		$newstr = '';
		$strlen = strlen($text);
		for($i = 0; $i < $strlen; $i++ ){
			$letter++;
			if ( $letter > 31 ){
				$letter = 0;
			}
			$neword = ord($text{$i}) + ord($key{$letter});
			if ( $neword > 255 ){
				$neword -= 256;
			}
			$newstr .= chr($neword);
		}
		return base64_encode($newstr);
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
	
	public function listAlgos(){
		if (!$this->no_mcrypt){
			return mcrypt_list_algorithms();
		}
		return array();
	}
}