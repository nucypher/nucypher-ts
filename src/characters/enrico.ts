import { PublicKey, SecretKey } from '@nucypher/nucypher-core';

import { MessageKit } from '../core';
import { toBytes } from '../utils';

const accessControlConditions = [
  {
    contractAddress: "",
    standardContractType: "timestamp",
    chain: "ethereum",
    method: "eth_getBlockByNumber",
    parameters: ["latest"],
    returnValueTest: {
      comparator: ">=",
      value: "1651276942"
    },
  },
  {operator: "or"},
  {
    contractAddress: "",
    standardContractType: "timestamp",
    chain: "ethereum",
    method: "eth_getBlockByNumber",
    parameters: ["latest"],
    returnValueTest: {
      comparator: "<=",
      value: "1651276942"
    },
  },
];

export class Enrico {
  public readonly policyEncryptingKey: PublicKey;
  public readonly verifyingKey: PublicKey;

  constructor(policyEncryptingKey: PublicKey, verifyingKey?: PublicKey) {
    this.policyEncryptingKey = policyEncryptingKey;
    this.verifyingKey = verifyingKey ?? SecretKey.random().publicKey();
  }

  public encryptMessage(plaintext: Uint8Array | string): MessageKit {
    return new MessageKit(
      accessControlConditions,
      this.policyEncryptingKey,
      plaintext instanceof Uint8Array ? plaintext : toBytes(plaintext)
    );
  }
}
