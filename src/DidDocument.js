import { DIDDocument } from 'did-document';
import { secretbox, box, sign, randomBytes } from "tweetnacl";
import {
  decodeUTF8,
  encodeBase64,
  decodeBase64
} from "tweetnacl-util";
import Axios from 'axios';

/**
 * Load a DID Document from the server
 */
DIDDocument.prototype.load = async function() {
    let did = this.id;

    // TODO: Load DID document from server
    let HOST = 'http://localhost:5001/';

    let response = await Axios.get(HOST + 'load?did=' + did);
    let document = response.data.data.document;
    let doc = new DIDDocument(document, document['@context']);
    return doc;
}

/**
 * Save a DID Document to the server
 */
DIDDocument.prototype.commit = async function(didDocument) {
    let HOST = 'http://localhost:5001/';
    try {
        let response = await Axios.post(HOST + 'commit', {
            params: {
                document: didDocument
            }
        });

        return true;
    } catch (err) {
        if (typeof err.response.data == 'object' && err.response.data.status == 'fail') {
            throw new Error(err.response.data.message);
        }

        throw err;
    }
}

DIDDocument.prototype.createProof = function(privateKeyHex) {
    let privateKeyBytes = Buffer.from(privateKeyHex, 'hex');

    let data = this.toJSON();
    delete data['proof'];

    let messageUint8 = decodeUTF8(JSON.stringify(data));
    let signature = encodeBase64(sign.detached(messageUint8, privateKeyBytes));
    
    this.proof = {
        alg: 'ES256K',
        signature: signature
    };
}

DIDDocument.prototype.verifyProof = function() {
    let signature = this.proof.signature;
    let data = this.toJSON();
    delete data['proof'];

    let signKey = this.publicKey.find(entry => entry.id.includes('sign'));
    let signKeyBytes = Buffer.from(signKey.publicKeyHex, 'hex');

    let messageUint8 = decodeUTF8(JSON.stringify(data));
    return sign.detached.verify(messageUint8, decodeBase64(signature), signKeyBytes);
}

export default DIDDocument;