use wasm_bindgen::prelude::*;
use idb::{Database, Error, Factory,TransactionMode,KeyPath,IndexParams,ObjectStoreParams};
use serde::{Deserialize,Serialize};
use serde_wasm_bindgen::Serializer;
use wasm_bindgen::JsValue;
use hex::FromHex;
use hex::encode;
use crypto::{aes, blockmodes, symmetriccipher,buffer};
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use bdk::bitcoin::{Txid,TxIn,TxOut};
use bdk::bitcoin::blockdata::transaction::OutPoint;
use bdk::bitcoin::hashes::Hash;
use bdk::blockchain::esplora::EsploraBlockchain;
use bdk::miniscript;
use bdk::bitcoin::secp256k1::{KeyPair,Secp256k1,Message};
use bdk::bitcoin::consensus::Encodable;
use bdk::bitcoin::{Script, Transaction,Address,Network,Witness,Sequence};
use bdk::bitcoin::LockTime;
use bdk::keys::{DerivableKey, GeneratableKey, GeneratedKey, ExtendedKey, bip39::{Mnemonic, WordCount, Language}};
use x25519_dalek::{PublicKey,StaticSecret};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use web_sys::console;
use serde_wasm_bindgen::from_value;
//use crate::utils;
use crate::utils::SeedStore;
use std::collections::HashMap;

mod utils;

#[derive(Debug, Serialize, Deserialize,Default,Clone)]
pub struct Utxo{
	pub utxo : String,
	pub btc : u64,
	pub txid : String,
	pub confirmed : bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EsploraStatus{
	pub confirmed : bool,
	pub block_height : Option<u64>,
	pub block_hash : Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EsploraUtxos{
	pub txid : String,
	pub vout : u64,
	pub status : EsploraStatus,
	pub value : u64,
}

pub struct ServerWallet{
	esplora_url : Option<String>,
	blockchain : Option<EsploraBlockchain>,
	keypair : Option<KeyPair>,
	address : Option<Address>,
	name : String,
	unspent_utxos : Option<Vec<Utxo>>,
}

impl ServerWallet{
    pub fn new() -> ServerWallet {
        ServerWallet { 
        	esplora_url : None,
        	blockchain : None,
        	keypair : None,
        	unspent_utxos : None,
        	address : None,
        	name : String::new()
        }
    }

    pub async fn sync(&mut self) -> String{
		let instance_name;
		if self.name != ""{ instance_name = self.name.clone(); }else{ return "{\"Error\":\"Wallet not initialized.\"}".to_string();}
		let database_res = &Self::create_database(instance_name).await;
		let database = 	match database_res{
	   		Ok(database) => database,
	   		Err(_) => return "{\"Error\":\"Databse error.\"}".to_string(),
	   	};
		let esplora_server_url = match &self.esplora_url{
			Some(url) => url.to_string(),
			None => return "{\"Error\":\"Wallet not initialized.\"}".to_string(),
		};
		let address = match &self.address{
			Some(addr) => addr,
			None => return "{\"Error\":\"Wallet not initialized.\"}".to_string(),
		};

		let client = reqwest::Client::new();
		let url_str = format!("{}/address/{}/utxo",&esplora_server_url,&address);
		let response = match client
			.get(url_str)
			.send()
			.await{
				Ok(response) => response,
				Err(_) => return "error".to_string(),
			};
		if response.status().is_success() {
			let body = response.text().await.unwrap();
			match serde_json::from_str::< Vec<EsploraUtxos> >(&body){
				Ok(eutxos) => {
					let mut outpoint_vec = Vec::new();
					for etxo in eutxos{
						let utxo = Utxo{
							utxo : format!("{}:{}",etxo.txid,etxo.vout),
							btc : etxo.value,
							txid : etxo.txid.clone(),
							confirmed : etxo.status.confirmed,
						};
						outpoint_vec.push(utxo);
				
					}
					self.unspent_utxos = Some(outpoint_vec);
					return "{\"Success\":\"Sync Complete.\"}".to_string();
				}
				Err(e) => return format!("{:?}",e),//return "{\"Error\":\"Failed to deserialize transaction:.\"}".to_string(),
			};
		}
		return "{\"Error\":\"Wallet not initialized.\"}".to_string();
	}

    pub async fn create_wallet(&self, instance_name : String, password : String) -> String {	
		let database_res = Self::create_database(instance_name.clone()).await;
		let database = 	match database_res{
	   		Ok(database) => database,
	   		Err(_) => return "{\"Error\":\"Databse error\"}".to_string(),
	   	};
	   	let js_val : JsValue = JsValue::from_f64(1.0);
	   	let res = match Self::get_mnemonic(&database,js_val.clone()).await{
	   		Ok(res) => res,
	   		Err(_) => return "{\"Error\":\"Database error\"}".to_string(),
	   	};
	   	match res{
	   		Some(_) => return "{\"Result\":\"Wallet already exists!\"}".to_string(), 
	   		None => {
	   			//Set seedphrase
	   			let mnemonic: GeneratedKey<_, miniscript::Segwitv0> = Mnemonic::generate((WordCount::Words12, Language::English)).unwrap();
	   			let mnemonic_words = mnemonic.to_string();
	   			//Hash password, use this to encrypt seedphrase
	   			let mut hasher = Sha256::new();
				hasher.input_str(&password);
				let pass_hash = hasher.result_str();
				let pass_bytes = Self::hex_string_to_u8_array(&pass_hash).unwrap(); //This is fine because we set explicitly
				let iv: [u8; 16] = [0; 16];
				let encrypted_data = Self::aes_encrypt(mnemonic_words.as_bytes(), &pass_bytes, &iv).ok().unwrap(); //Same reason ^
	    		let encrypted_hex_string = Self::array_to_hex(&encrypted_data);
	   			match Self::set_mnemonic(&database,encrypted_hex_string.clone(),js_val).await{
	   				Ok(_) => {
						let mut result : String = "{\"Result\":\"".to_string();
						result.push_str(&format!("{}",mnemonic_words));
						result.push_str("\"}");
						return result;
	   				}
	   				Err(_) => return "{\"Error\":\"Database error.\"}".to_string(),
	   			};
	   		} 
	   	}
    }
    pub async fn generate_wallet(&self, instance_name : String, password : String, seedphrase : String) -> String{
		let database_res = Self::create_database(instance_name.clone()).await;
		let database = 	match database_res{
	   		Ok(database) => database,
	   		Err(_) => return "{\"Error\":\"Databse error\"}".to_string(),
	   	};
	   	let js_val : JsValue = JsValue::from_f64(1.0);
	   	let res = match Self::get_mnemonic(&database,js_val.clone()).await{
	   		Ok(res) => res,
	   		Err(_) => return "{\"Error\":\"Database error\"}".to_string(),
	   	};
	   	match res{
	   		Some(_) => return "{\"Result\":\"Wallet already exists!\"}".to_string(), 
	   		None => {
	   			//Set seedphrase
	   			let mnemonic_words = seedphrase;
	   			//Hash password, use this to encrypt seedphrase
	   			match Mnemonic::parse(&mnemonic_words){
	   				Ok(_) => (),
	   				Err(_) => return "{\"Error\":\"Invalid mnemonic.\"}".to_string(),
	   			};
	   			let mut hasher = Sha256::new();
				hasher.input_str(&password);
				let pass_hash = hasher.result_str();
				let pass_bytes = Self::hex_string_to_u8_array(&pass_hash).unwrap(); //This is fine because we set explicitly
				let iv: [u8; 16] = [0; 16];
				let encrypted_data = Self::aes_encrypt(mnemonic_words.as_bytes(), &pass_bytes, &iv).ok().unwrap(); //Same reason ^
	    		let encrypted_hex_string = Self::array_to_hex(&encrypted_data);
	   			match Self::set_mnemonic(&database,encrypted_hex_string.clone(),js_val).await{
	   				Ok(_) => {
						let mut result : String = "{\"Result\":\"".to_string();
						result.push_str(&format!("{}",mnemonic_words));
						result.push_str("\"}");
						return result;
	   				}
	   				Err(_) => return "{\"Error\":\"Database error.\"}".to_string(),
	   			};
	   		} 
	   	}
    }

    pub async fn init(&mut self, instance_name : String, password : String, network : &str, esplora_url : String) -> String {
		let network = match network {
			"mainnet" => Network::Bitcoin,
			"m" => Network::Bitcoin,
			"testnet" => Network::Testnet,
			"t" => Network::Testnet,
			&_ => Network::Testnet,
		};
		let blockchain = EsploraBlockchain::new(&esplora_url, 20);
		self.blockchain = Some(blockchain);
		self.esplora_url = Some(esplora_url);
		self.name = instance_name.clone();
		let database_res = Self::create_database(instance_name.clone()).await;
		let database = 	match database_res{
	   		Ok(database) => database,
	   		Err(_) => return "{\"Error\":\"Databse error\"}".to_string(),
	   	};
	   	let js_val : JsValue = JsValue::from_f64(1.0);
	   	let res = match Self::get_mnemonic(&database,js_val.clone()).await{
	   		Ok(res) => res,
	   		Err(_) => return "{\"Error\":\"Database error\"}".to_string(),
	   	};
	   	match res{
	   		Some(data) => {
	   			//Fetch from index DB
	   			//return format!("{}",data);
	   			let seed = match serde_json::from_str::<utils::SeedStore>(&format!{"{}",data}){
	   				Ok(seed) => seed,
	   				Err(_) => return "{\"Error\":\"Database error\"}".to_string(),
	   			};
		   		//Hash password for decrypt
		   		let mut hasher = Sha256::new();
				hasher.input_str(&password);
				let pass_hash = hasher.result_str();
				let pass_bytes = Self::hex_string_to_u8_array(&pass_hash).unwrap(); //Explicit
				let iv: [u8; 16] = [0; 16];
				//Grab encrypted string and decrypt it
				let encrypted_hex_string = seed.mnemonic;
		   		let reconstructed_bytes = Self::hex_to_vec(&encrypted_hex_string).unwrap(); //Explicit
		   		let decrypted_data = match Self::aes_decrypt(&reconstructed_bytes[..], &pass_bytes, &iv){
			   		Ok(decrypted_data) => decrypted_data,
			   		Err(_) => return "{\"Error\":\"Decryption failed. Wrong password.\"}".to_string() , 
			   	};
			   	match String::from_utf8(decrypted_data){
			   		Ok(mnemonic_words) => {
			   			let secp = Secp256k1::new();
			   			let mnemonic  = Mnemonic::parse(&mnemonic_words).unwrap();
						let xkey: ExtendedKey = mnemonic.into_extended_key().unwrap();
						let xprv = xkey.into_xprv(network).unwrap();
						//Insert bip 84 here
						let keypair =xprv.to_keypair(&secp);
					    let bitcoin_pub : bdk::bitcoin::PublicKey = bdk::bitcoin::PublicKey::new(keypair.public_key());
					    let segwit_address = Address::p2wpkh(&bitcoin_pub,network).unwrap();
						self.address = Some(segwit_address);
						self.keypair = Some(keypair);
						return "{\"Result\":\"Wallet successfully loaded.\"}".to_string();
			   		}
			   		Err(_) => return "{\"Error\":\"Decryption failed. Wrong password.\"}".to_string(), 
			   	};
	   		}
	   		None =>  return "{\"Error\":\"You need to call create wallet first!\"}".to_string(),
	   	}
	}

	pub async fn has_wallet(&self,instance_name : String) -> String{
		let database_res = Self::create_database(instance_name.clone()).await;
		let database = 	match database_res{
	   		Ok(database) => database,
	   		Err(_) => return "{\"Error\":\"Databse error\"}".to_string(),
	   	};
	   	let js_val : JsValue = JsValue::from_f64(1.0);
	   	let res = match Self::get_mnemonic(&database,js_val).await{
	   		Ok(res) => res,
	   		Err(_) => return "{\"Error\":\"Database error\"}".to_string(),
	   	};
	   	match res{
	   		Some(_) => return "{\"Result\":\"Wallet exists.\"}".to_string(),
			None => return "{\"Result\":\"No Wallet found.\"}".to_string(),
		};
	}

	pub async fn broadcast_tx(&self, tx_str : String) -> String{
		let blockchain = match &self.blockchain{
			Some(blockchain) => blockchain,
			None => return "{\"Error\":\"Wallet not initialized.\"}".to_string(),
		};
		let tx = match serde_json::from_str::<Transaction>(&tx_str){
			Ok(tx) => tx,
			Err(_) => return "{\"Error\":\"Failed to deserialize transaction:.\"}".to_string(),
		};
		match blockchain.broadcast(&tx).await  {
			Ok(_) => { 
				let mut result : String = "{\"Result\":\"".to_string();
				result.push_str(&format!("{}", tx.txid()));
				result.push_str("\"}");
				return result;
			}
			Err(_) =>  return "{\"Error\":\"Failed to broadcast transaction.\"}".to_string(),
		};
	}

	pub async fn estimate_fee(&self, number_of_blocks : i32) -> String{
		let esplora_server_url = match &self.esplora_url{
			Some(url) => url.to_string(),
			None => return "{\"Error\":\"Wallet not initialized.\"}".to_string(),
		};
		let mut path = String::new();
		path.push_str(&esplora_server_url);
		path.push_str("/fee-estimates");
		let fee_histo_text  = match reqwest::get(path).await{
			Ok(fee_histo_text) => fee_histo_text,
			Err(_) => return "{\"Error\":\"Connection error, esplora url.\"}".to_string(),
		};
		let fee_histo = match fee_histo_text.text().await{
			Ok(fee_histo) => fee_histo,
			Err(_) => return "{\"Error\":\"Failed to parse result. Try again.\"}".to_string(),
		};
		let dict : HashMap<String, f64>   = serde_json::from_str(&fee_histo).unwrap();
		let mut fee_est : f64 = 0.0;
		if let  Some(value) = dict.get(&number_of_blocks.to_string()) {
			fee_est = *value;
		}
		fee_est = fee_est*500.0;
		let fee_int = fee_est as i32;
		let mut fee_64 : u64 = fee_int as u64;
		fee_64 += 260;
		let mut result : String = "{\"Result\":\"".to_string();
		result.push_str(&format!("{}",fee_64));
		result.push_str("\"}");
		return result;
	}

	pub fn gen_seed_phrase(&self) -> String{
		let mnemonic: GeneratedKey<_, miniscript::Segwitv0> = Mnemonic::generate((WordCount::Words12, Language::English)).unwrap();
	   	let mnemonic_words = mnemonic.to_string();
	   	mnemonic_words
	}

    pub async fn get_mnemonic(database: &Database, id : JsValue) -> Result<Option<serde_json::Value>, Error> {
	    let transaction = database
	        .transaction(&["wallet"], TransactionMode::ReadOnly)
	        .unwrap();
	    let store = transaction.object_store("wallet").unwrap();
	    let seedphrase: Option<JsValue> = store.get(id).await?;
	    let seedphrase: Option<serde_json::Value> = seedphrase
	        .map(|seedphrase| serde_wasm_bindgen::from_value(seedphrase).unwrap());	
	    transaction.done().await?;
	    Ok(seedphrase)
	}

	pub async fn set_mnemonic(database: &Database, seedphrase : String, id : JsValue) -> Result<JsValue, Error> {
	    let transaction = database.transaction(&["wallet"], TransactionMode::ReadWrite)?;
	    let store = transaction.object_store("wallet").unwrap();
	    let seedstore = serde_json::json!({
	        "mnemonic": seedphrase,
	    });
	    let id = store
	        .add(
	            &seedstore.serialize(&Serializer::json_compatible()).unwrap(),
	            Some(&id),
	        )
	        .await?;
	    transaction.commit().await?;
	    Ok(id)
	}

	pub async fn create_database(instance_name : String) -> Result<Database, Error> {
	    let factory = Factory::new()?;
	    let mut open_request = factory.open(&instance_name, Some(1)).unwrap();
	    open_request.on_upgrade_needed(move |event| {
	        let database = event.database().unwrap();
	        let mut store_params = ObjectStoreParams::new();
	        store_params.auto_increment(false);
	        store_params.key_path(None);
	        let store = database
	            .create_object_store("wallet", store_params.clone())
	            .unwrap();
	        let mut index_params = IndexParams::new();
	        index_params.unique(true);
	        store
	            .create_index("mnemonic'", KeyPath::new_single("mnemonic"), Some(index_params))
	            .unwrap();
	    });
	    open_request.await
	}

	pub fn is_address(&self, address : String) -> bool{
		match address.parse::<Address>(){
			Ok(_) => return true,
			Err(_) => return false,
		};
	}

	pub fn hash_prevouts(txins : Vec<TxIn>) -> String{
		//Double hash the prevouts from the txin vec
		let mut hex_str = String::new();
		for txin in txins{
			let mut txid_arr = Self::hex_to_vec(&format!("{:?}",txin.previous_output.txid)).unwrap();
			txid_arr.reverse();
			hex_str.push_str(&Self::array_to_hex(&txid_arr));
			let mut u32_as_bytes: [u8; 4] = txin.previous_output.vout.to_be_bytes();
			u32_as_bytes.reverse();
	    	hex_str.push_str(&Self::array_to_hex(&u32_as_bytes));
		}
		return Self::double_sha(hex_str);
		}
	pub fn hash_sequence(txins : Vec<TxIn>) -> String{
		let mut hex_str = String::new();
		for txin in txins{
			let mut u32_as_bytes: [u8; 4] = txin.sequence.0.to_be_bytes();
			u32_as_bytes.reverse();
	    	hex_str.push_str(&Self::array_to_hex(&u32_as_bytes));
		}
		return Self::double_sha(hex_str);
	}
	pub fn hash_outputs(txouts : Vec<TxOut>) ->String{
		let mut hex_str = String::new();
		for txout in txouts{
			let mut u64_as_bytes: [u8; 8] = txout.value.to_be_bytes();
			u64_as_bytes.reverse();
	    	hex_str.push_str(&Self::array_to_hex(&u64_as_bytes));
	    	let len = txout.script_pubkey.as_bytes().len();
	    	let len_arr = vec![len as u8];
	    	hex_str.push_str(&Self::array_to_hex(&len_arr));
	    	hex_str.push_str(&Self::array_to_hex(&txout.script_pubkey.as_bytes()));
		}
		return Self::double_sha(hex_str);
	}
	pub fn double_sha(hex_str : String) -> String{
		let mut hasher = Sha256::new();
		hasher.input(&Self::hex_to_vec(&hex_str).unwrap());
		let hex = hasher.result_str();
		let mut doubler_haser = Sha256::new();
		doubler_haser.input(&Self::hex_to_vec(&hex).unwrap());
		let double_hex = doubler_haser.result_str();
		return double_hex;
	}

	pub async fn send_btc(&self, btc_address_str : String, amount_sats_str : String, fee_64 : u64) -> String{
		let my_address = match &self.address{
			Some(addr) => addr,
			None => return "{\"Error\":\"Wallet needs to sync.\"}".to_string(),
		};
	
		let keypair = match &self.keypair{
	    	Some(keypair) => keypair,
	    	None => return "{\"Error\":\"Wallet not initialized.\"}".to_string(),
	    };

		let unbound = match &self.unspent_utxos{
	    	Some(u) => u,
	    	None => return "{\"Error\":\"Wallet not initialized.\"}".to_string(),
	    };


	    let address_strs : Vec<&str> = btc_address_str.split(" ").collect();
		let mut address_v : Vec<Address> = Vec::new();
		for addr in address_strs{
			match addr.parse::<Address>(){
				Ok(add) => address_v.push(add),
				Err(_) => return "{\"Error\":\"Failed to parse address.\"}".to_string(),
			};
		}
		let mut amount_sats_vec : Vec<u64> = Vec::new();
		let amount_sats_strs : Vec<&str> = amount_sats_str.split(" ").collect();
		for amount in amount_sats_strs{
			match amount.parse::<u64>(){
				Ok(amt) => amount_sats_vec.push(amt),
				Err(_)=>return "{\"Error\":\"Failed to parse amount.\"}".to_string(),
			}
		}
		let mut total_amount =0;
		for amt in &amount_sats_vec{
			total_amount += amt;
		}

		let instance_name;
		if self.name != ""{ instance_name = self.name.clone(); }else{ return "{\"Error\":\"Wallet not initialized.\"}".to_string();}
		let database_res = &Self::create_database(instance_name).await;
		let database = 	match database_res{
	   		Ok(database) => database,
	   		Err(_) => return "{\"Error\":\"Databse error\"}".to_string(),
	   	};
	   	let mut txin_vec = Vec::new();
	   	let mut txout_vec = Vec::new();
	   	let mut txin_values = Vec::new(); //This lets us sign without pipping the node twice

	   	let mut total_spend : u64  = 0;
		for utxo in unbound { 
			total_spend += utxo.btc;
			let outpoint = utils::convert_to_outpoint(&utxo.utxo);
			let txin = TxIn{
				previous_output : outpoint,
				script_sig : Script::new(),
				sequence: Sequence::MAX,
        		witness: Witness::new(),
			};
			txin_vec.push(txin);
			txin_values.push(utxo.btc);
			if total_spend > (fee_64+total_amount) {
				break;
			}
		}
		
		if total_spend < fee_64+total_amount{
			return "{\"Error\":\"Insuffient Funds.\"}".to_string();
		}
		let change = total_spend - (fee_64+total_amount);

		let mut rec_index = 0;
		for rec_addr in address_v{
			let output : bdk::bitcoin::TxOut =  bdk::bitcoin::TxOut{
		        value : amount_sats_vec[rec_index],
		        script_pubkey: rec_addr.script_pubkey(),
		    };
		    txout_vec.push(output);
		    rec_index += 1;
		}

	    let change : bdk::bitcoin::TxOut =  bdk::bitcoin::TxOut{
	        value : change,
	        script_pubkey: my_address.script_pubkey(),
	    };
	    txout_vec.push(change);

	    let locktime = LockTime::from_height(0).expect("valid height");
	    let unsigned_tx = Transaction{
	    	version: 2,
	        lock_time : locktime.into(),
	        input : txin_vec.clone(),
	        output : txout_vec.clone(),
	    };
	
		let signed_tx = self.sign_transaction(unsigned_tx,keypair,my_address.clone(),txin_values);

	    let tx_str = serde_json::to_string(&signed_tx).unwrap();
		let txid_str = signed_tx.txid().to_string();
		self.broadcast_tx(tx_str).await; 


		let mut result : String = "{\"Result\":\"".to_string();
		result.push_str(&txid_str);
		result.push_str("\"}");
		return result;
	}

	fn sign_transaction(&self, unsigned_tx : Transaction, keypair : &KeyPair, my_address : Address , txin_values : Vec<u64>) -> Transaction{
		//SIGNING
		let txin_vec = unsigned_tx.input.clone();
		let txout_vec = unsigned_tx.output.clone();
	    let secp = Secp256k1::new();
	    let mut hex_str_to_sign = "02000000".to_string();

	    let hash_prevouts = Self::hash_prevouts(txin_vec.clone());
	    hex_str_to_sign.push_str(&hash_prevouts);

	    let hash_sequence = Self::hash_sequence(txin_vec.clone());
	    hex_str_to_sign.push_str(&hash_sequence);
	    
	    let base_hex_str = hex_str_to_sign;
	    let mut signed_txin_vec = Vec::new();
	    let mut tx_val_index = 0;
	    for mut txin in txin_vec{
	    	hex_str_to_sign = base_hex_str.clone();
		    let this_outpoint = txin.previous_output;
		    let mut this_outpoint_arr = Self::hex_to_vec(&format!("{:?}",this_outpoint.txid)).unwrap();
			this_outpoint_arr.reverse();
		    hex_str_to_sign.push_str(&Self::array_to_hex(&this_outpoint_arr));

			let mut u32_as_bytes: [u8; 4] = this_outpoint.vout.to_be_bytes();
			u32_as_bytes.reverse();
	    	hex_str_to_sign.push_str(&Self::array_to_hex(&u32_as_bytes));

	    	//and old school script command for verification
	    	let spk =  my_address.script_pubkey();
	    	let mut script_bytes = spk.as_bytes();
	    	script_bytes = &script_bytes[2..]; // strip segwit OP_0 and pushbytes
	    	let pub_key_hash = Self::array_to_hex(script_bytes);
	    	hex_str_to_sign.push_str("1976a914");
			hex_str_to_sign.push_str(&pub_key_hash);
	    	hex_str_to_sign.push_str("88ac");

	    	//Add Input value and sequence
	    	let input_val = txin_values[tx_val_index];
	    	let mut u64_as_bytes: [u8; 8] = input_val.to_be_bytes();
	    	u64_as_bytes.reverse();
	    	hex_str_to_sign.push_str(&Self::array_to_hex(&u64_as_bytes));

	    	let mut seq_bytes: [u8; 4] = txin.sequence.0.to_be_bytes();
			seq_bytes.reverse();
			hex_str_to_sign.push_str(&Self::array_to_hex(&seq_bytes));

			let hash_outputs = Self::hash_outputs(txout_vec.clone());
			hex_str_to_sign.push_str(&hash_outputs);

			//Add locktime and sighash
			hex_str_to_sign.push_str("00000000");//00000000
			hex_str_to_sign.push_str("01000000");//01000000

			//Sign the message using the keypair
			let final_hex_arr = Self::hex_to_vec(&Self::double_sha(hex_str_to_sign)).unwrap();
			let final_hex = Self::array_to_hex(&final_hex_arr);
			let message = Message::from_slice(&Self::hex_string_to_u8_array(&final_hex).unwrap()).expect("32 bytes");

	    	let sig = secp.sign_ecdsa(&message, &keypair.secret_key());
	    	let mut sig_hex_str =  format!("{:?}",sig);
	    	sig_hex_str.push_str("01");

		    //Construct witness from signature
		    let mut witness = String::new();
		    witness.push_str("02");
		    let sig_len = Self::hex_to_vec(&sig_hex_str).unwrap().len();
		    let sgl = vec![sig_len as u8];
		    witness.push_str(&Self::array_to_hex(&sgl));
		   	witness.push_str(&sig_hex_str);

		    let pubkey = Self::array_to_hex(&keypair.public_key().serialize());
		    let pubkey_len = Self::hex_to_vec(&pubkey).unwrap().len();
		    let pkl = vec![pubkey_len as u8];
		    witness.push_str(&Self::array_to_hex(&pkl));
		    witness.push_str(&pubkey);

		    let wit_vec = vec![Self::hex_to_vec(&sig_hex_str).unwrap(),Self::hex_to_vec(&pubkey).unwrap()];

		    txin.witness = Witness::from_vec(wit_vec);
		    signed_txin_vec.push(txin);
		    tx_val_index += 1;
		}

	    let signed_tx = Transaction{
	    	version: unsigned_tx.version,
	        lock_time : unsigned_tx.lock_time,
	        input : signed_txin_vec,
	        output : unsigned_tx.output,
	    };
	    signed_tx
	}

	pub fn aes_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
	    let mut encryptor = aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);
	    let mut final_result = Vec::<u8>::new();
	    let mut read_buffer = buffer::RefReadBuffer::new(data);
	    let mut buffer = [0; 4096];
	    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
	    loop {
	        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;
	        final_result.extend(
	            write_buffer
	                .take_read_buffer()
	                .take_remaining()
	                .iter()
	                .map(|&i| i),
	        );
	        match result {
	            BufferResult::BufferUnderflow => break,
	            BufferResult::BufferOverflow => {}
	        }
	    }
	    Ok(final_result)
	}
	pub fn aes_decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
	    let mut decryptor = aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);
	    let mut final_result = Vec::<u8>::new();
	    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
	    let mut buffer = [0; 4096];
	    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
	    loop {
	        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
	        final_result.extend(
	            write_buffer
	                .take_read_buffer()
	                .take_remaining()
	                .iter()
	                .map(|&i| i),
	        );
	        match result {
	            BufferResult::BufferUnderflow => break,
	            BufferResult::BufferOverflow => {}
	        }
	    }

	    Ok(final_result)
	}
	pub fn hex_string_to_u8_array(hex_str: &str) -> Result<[u8; 32], hex::FromHexError> {
	    let bytes = Vec::from_hex(hex_str)?;
	    println!("Byte length:{}", bytes.len());
	    if bytes.len() == 32 {
	        let mut result = [0; 32];
	        result.copy_from_slice(&bytes);
	        Ok(result)
	    } else {
	        // If the length is not 32, return an error or handle the case accordingly
	        Err(hex::FromHexError::InvalidStringLength)
	    }
	}
	pub fn hex_to_vec(hex_string: &str) -> Option<Vec<u8>> {
	    if hex_string.len() % 2 != 0 { return None; }
	    let mut bytes = Vec::new();
	    for chunk in hex_string.as_bytes().chunks(2) {
	        if let Ok(byte) = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16) {
	            bytes.push(byte);
	        }else{
	            return None; 
	        }
	    }
	    Some(bytes)
	}
	pub fn array_to_hex(data: &[u8]) -> String {
	    let hex_string: String = data.iter()
	        .map(|byte| format!("{:02x}", byte)) // Convert each byte to its hexadecimal representation
	        .collect();

	    hex_string
	}
}