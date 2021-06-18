"use strict";


/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setupCipher = lib.setupCipher,
    encryptwithGCM = lib.encryptwithGCM,
    decryptWithGCM = lib.decryptWithGCM,
    bitarraySlice = lib.bitarraySlice,
    bitarrayToString = lib.bitarrayToString,
    stringToBitarray = lib.stringToBitarray,
    bitarrayToBase64 = lib.bitarrayToBase64,
    base64ToBitarray = lib.base64ToBitarray,
    stringToPaddedBitarray = lib.stringToPaddedBitarray,
    paddedBitarrayToString = lib.paddedBitarrayToString,
    randomBitarray = lib.randomBitarray,
    bitarrayEqual = lib.bitarrayEqual,
    bitarrayLen = lib.bitarrayLen,
    bitarrayConcat = lib.bitarrayConcat,
    objectHasKey = lib.objectHasKey;


/********* Implementation ********/


var keychainClass = function() {

  // Private instance variables.
    
  // Use this variable to store everything you need to.
  var priv = {
    secrets: { /* Your secrets here */ },
    data: { 
      /* Non-secret data here */ 
      // Initialize the kvs struct in priv.data
      kvs: {

      },
    }
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;

  // Length of the KDF salt
  var KDF_SALT_LEN = 128;
  
  // Length of the keys (in bits).
  var HMAC_KEY_LEN = 128;
  var AES_KEY_LEN = 128;
  
  // Flag to indicate whether password manager is "ready" or not
  var ready = false;

  var keychain = {};

  /** 
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {
    // A secure password manager is *not allowed* to include the master 
    // password (or even a hash of it or any other values that would leak 
    // information about it), or any of the secret keys used, in 
    // the serialized password database on disk.
    priv.data.version = "CS 255 Password Manager v1.0";

    // Create a random bit array of length 128 bits, and have that serve
    // as the salt for PBKDF2.
    priv.secrets["master_salt"] = randomBitarray(KDF_SALT_LEN);

    // master_key <- KDF(master_password, master_salt)
    priv.secrets["master_key"] = KDF(password, priv.secrets["master_salt"]);
    // key <- HMAC(master_key, salt)
    priv.secrets.hmac_key = HMAC(priv.secrets["master_key"], randomBitarray(HMAC_KEY_LEN));
    priv.secrets.aes_key = HMAC(priv.secrets["master_key"], randomBitarray(AES_KEY_LEN));

    // Go ahead and set up a cipher for AES since it will be used in both get()
    // and set() functions.
    priv.secrets.aes_cipher = setupCipher(bitarraySlice(priv.secrets.aes_key, 0, AES_KEY_LEN));

    // Indicate that the keychain is now ready to use.
    ready = true;

  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: boolean
    */
  keychain.load = function(password, repr, trustedDataCheck) {
    // Extract all of the data from repr.
    const keychain_load = JSON.parse(repr);
    const kvs_data = keychain_load["kvs"];
    const master_salt = keychain_load["master_salt"];
    const master_key = keychain_load["master_key"];

    // Check to see if the master_key that was in repr matches the one that we
    // compute using master_salt and password.
    const computed_master_key = KDF(password, master_salt);
    if (bitarrayToBase64(computed_master_key) !== bitarrayToBase64(master_key)) {
      return false;
    }
    
    // Check to see if the checksum of repr matches trustedDataCheck.
    const repr_checksum = bitarrayToBase64(SHA256(stringToBitarray(repr)));
    if (trustedDataCheck !== undefined && trustedDataCheck !== repr_checksum) {
      throw "Checksums do not match.";
    }
    
    // Store data in keychain.
    priv.data = kvs_data;
    priv.secrets.master_salt = master_salt;
    priv.secrets.master_key = master_key;

    // Indicate that the keychain is now ready to use.
    ready = true;
    return true;
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */ 
  keychain.dump = function() {
    if (!ready) {
      throw "Keychain not initialized."
    }
    // Create a keychain_dump JSON object and dump all of the necessary
    // information for restoring a keychain.
    let keychain_dump = { };
    keychain_dump["master_salt"] = priv.secrets["master_salt"];
    keychain_dump["master_key"] = priv.secrets["master_key"];
    keychain_dump["kvs"] = priv.data.kvs;

    const sha256_checksum = bitarrayToBase64(SHA256(stringToBitarray(JSON.stringify(keychain_dump))));
    return [ JSON.stringify(keychain_dump), sha256_checksum ];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: string
    */
  keychain.get = function(name) {
    if (!ready) {
      throw "Keychain not initialized."
    }
    // Compute HMAC(hmac_key, domain)
    const hmac_domain = bitarrayToBase64(HMAC(priv.secrets.hmac_key, name));

    // If there is no entry in the KVS that matches the given domain, then 
    // return null.
    if (!priv.data.kvs[hmac_domain]) {
      return null;
    }

    const plaintext_bitarray = decryptWithGCM(priv.secrets.aes_cipher, priv.data.kvs[hmac_domain]);

    // decryptWithGCM() returns a bitarray, so convert the bitarray to a string
    // prior to returning.
    return bitarrayToString( plaintext_bitarray );
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  keychain.set = function(name, value) {
    if (!ready) {
      throw "Keychain not initialized."
    }
    // Compute HMAC(hmac_key, domain)
    const hmac_domain = bitarrayToBase64(HMAC(priv.secrets.hmac_key, name));
    const aes_value = encryptwithGCM(priv.secrets.aes_cipher, stringToBitarray(value));
    
    // Store the key-value pair. This should, by default, overwrite whatever
    // value was already paired with hmac_domain. Additionally, if the 
    // key-value pair does not exist already, then it will be created.
    priv.data.kvs[hmac_domain] = aes_value;
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: boolean
  */
  keychain.remove = function(name) {
    if (!ready) {
      throw "Keychain not initialized."
    }
    // Compute HMAC(hmac_key, domain)
    const hmac_domain = bitarrayToBase64(HMAC(priv.secrets.hmac_key, name));
    
    // If a record with the specified domain does not exist, then return false.
    if (!priv.data.kvs[hmac_domain]) {
      return false;
    }

    // If a record with the specified domain exists, then delete the key-value
    // pair from the keychain, and return true.
    delete priv.data.kvs[hmac_domain];
    return true;
  };

  return keychain;
};

module.exports.keychain = keychainClass;
