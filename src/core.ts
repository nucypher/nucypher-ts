import { Capsule, MessageKit as CoreMessageKit, PublicKey, SecretKey } from '@nucypher/nucypher-core';

import { toBytes } from './utils';

export class MessageKit extends CoreMessageKit{

    private readonly delimiter: number
    public readonly dcs: Array<Record<string, unknown>>;

    constructor(decryptionConditions: Array<Record<string, unknown>>, policyEncryptingKey: PublicKey, plaintext: Uint8Array) {
        super(
            policyEncryptingKey, 
            plaintext instanceof Uint8Array ? plaintext : toBytes(plaintext)
        )

        this.delimiter = 0xBC        
        this.dcs = decryptionConditions

    }

    public toNewBytes = () => {
        const conditionBytes = Buffer.from(JSON.stringify(this.dcs))
        const delimiterBytes = Uint8Array.from([this.delimiter])
        const mkBytes = super.toBytes()

        return Buffer.from(new Uint8Array([...conditionBytes, ...delimiterBytes, ...mkBytes]))
    }
}