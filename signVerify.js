const pkg = require('libsodium-wrappers');
const _sodium = pkg
const {base64_variants} = pkg
var fs = require('fs');
const _ = require('lodash');
const bodyParser = require('body-parser');
const process = require('process');
const axios = require('axios');

const { config } = require('process');
const { response } = require('express');

const express = require ('express');
const router = express.Router();


//HardCode Values 
// let searchJSON = require('./data.json')
// const aaa = 'Signature keyId="buyer-app.ondc.org|207|ed25519",algorithm="ed25519",created="1666201854",expires="1666205454",headers="(created) (expires) digest",signature="bx5JeQmGTW2B9Fihzji9ttMN+DVHKPdJYCVgnebJLcon8Oe8pzev8vObJlrsd4tPwVpgt6OtMrLHdoKGzOOJAw=="';


router.post('/', async(req, res) => {

const createSigningString = async (message, created, expires) => {
    if (!created) created = Math.floor(new Date().getTime() / 1000).toString();
    if (!expires) expires = (parseInt(created) + (24 * 60 * 60)).toString(); //Add required time to create expired
    await _sodium.ready;
    const sodium = _sodium;
    const digest = sodium.crypto_generichash(64, sodium.from_string(message));
    const digest_base64 = sodium.to_base64(digest, base64_variants.ORIGINAL);
    const signing_string =
 `(created): ${created}
 (expires): ${expires}
 digest: BLAKE-512=${digest_base64}`
    // console.log(signing_string);
    return { signing_string, expires, created }
 }



 const verifyMessage = async (signedString, signingString, publicKey) => {
    try {
        await _sodium.ready;
        const sodium = _sodium;
        return sodium.crypto_sign_verify_detached(sodium.from_base64(signedString, base64_variants.ORIGINAL), signingString, sodium.from_base64(publicKey, base64_variants.ORIGINAL));

       } catch (error) {
        console.log(error.message)
        return false
    }
 }



const verifyHeader = async (headerParts, body, public_key) => {
    // console.log(headerParts['created'] + "        "+ headerParts['expires']);
    // const { signing_string } = await createSigningString(JSON.stringify(body), headerParts['created'], headerParts['expires']);
    const { signing_string } = await createSigningString(body, headerParts['created'], headerParts['expires']);
    // console.log("recreated signing string:");
    // console.log(signing_string);
    // console.log("Signature going into verifyMessage Function:    "+headerParts['signature'] + "   Signing String input is going:   "+signing_string + "  Public Key:   "+public_key)
    const verified = await verifyMessage(headerParts['signature'], signing_string, public_key);
    console.log(verified)
    return verified;
 }


 const getProviderPublicKey = async (providers,  keyId) => {
    try {
        const provider = _.find(providers, ['ukId', keyId])
        return provider?.signing_public_key || false
    } catch(e){
        return false
    }
}


const lookupRegistry = async (subscriber_id, keyId) => {
    try {    
    const reqBody = {
        "type":"BAP",
        "domain": config.domain,
        "subscriber_id": subscriber_id
    }
 
    const response = await axios.post(`https://pilot-gateway-1.beckn.nsdl.co.in/lookup`, reqBody); //// `${process.env.REGISTRY}/lookup`, reqBody
    // console.log(response.data);
    if (!response.data) {
        return false
    }

    const public_key = await getProviderPublicKey(response.data, keyId)
    console.log("Public Key:   "+ public_key)
    if (!public_key) {
        return false
    }
    return public_key
    } catch(e){
        return false
    }
}

const remove_qoute = (quoteString) =>  {
        let re = /"([^"]*)"/; 
        retval = quoteString.match(re);
        // console.log(retval[1])
        return retval[1];
 } 


const split_auth_header = (auth_header) => {
    const header = auth_header.replace('Signature ', '');
    // console.log(header);
    
    let re = /\s*([^=]+)=([^,]+)[,]?/g;
    let m;
    let parts = {}
    while ((m = re.exec(header)) !== null) {
        if (m) {
            parts[m[1]] = remove_qoute(m[2]); // 
        }
    }
    return parts;
   
   
 }



const isSignatureValid = async (header, body) => {
    try{
        const headerParts = split_auth_header(header);
        // console.log("HeaderParts:    " + headerParts)
        // console.log(headerParts['keyId'])
    
        const keyIdSplit = headerParts['keyId'].split('|')
        // console.log(keyIdSplit[0])
        // console.log(keyIdSplit[1])
        // console.log(keyIdSplit[2])
        const subscriber_id = keyIdSplit[0]
        // console.log("SubscriberID:   " + subscriber_id)
        const keyId = keyIdSplit[1]
        // console.log("UniqueID:   " + keyId)
        
        // console.log("Algorithm is:   "+ headerParts['algorithm'])
        // console.log("Created is:   "+ headerParts['created'])
        // console.log("Expires is:   "+headerParts['expires'])
        // console.log("Headers is:   "+headerParts['headers'])
        // console.log("Signature is:   "+headerParts['signature'])

        const public_key = await lookupRegistry(subscriber_id, keyId)
       
        const isValid = await verifyHeader(headerParts, req.body, public_key)
        return isValid
    } catch(e){
        console.log('Error', e)
        return false
    }
}


const signVerified = await isSignatureValid(req.headers.authorization, req.body);
// const signVerified = await isSignatureValid(req.headers['proxy-authorization'], req.body);
// const signVerified = await isSignatureValid(req.headers['X-Gateway-Authorization'], req.body);
                            res.status(200).send(signVerified)  // if signverified= value, then verification is succesfull else failed.
                            
    

});

module.exports=router;
