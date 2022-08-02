import {
  EncryptedTreasureMap,
  PublicKey,
  SecretKey,
} from '@nucypher/nucypher-core';
import axios from 'axios';
import { ethers } from 'ethers';

import { EnactedPolicy } from '../policies/policy';
import { fromHexString } from '../utils';

import { Alice } from './alice';
import { Bob } from './bob';
import { Enrico } from './enrico';
import { tDecDecrypter } from './universal_bob';

async function getTDecConfig(
  configLabel: string
): Promise<{ [key: string]: any }> {
  const { data, status } = await axios.get(
    'https://raw.githubusercontent.com/nucypher/network-keys/master/network-keys.json'
  );
  return data[configLabel];
}

export async function generateTDecEntities(
  threshold: number,
  shares: number,
  provider: ethers.providers.Web3Provider,
  label: string,
  startDate: Date,
  endDate: Date,
  porterUri: string,
  aliceSecretKey: SecretKey = SecretKey.random()
): Promise<[Enrico, tDecDecrypter, EnactedPolicy]> {
  // const configuration = defaultConfiguration(chainId);
  const configuration = { porterUri };
  const bobSecretKey = SecretKey.random();
  const universalBob = new Bob(configuration, bobSecretKey);

  const godAlice = Alice.fromSecretKey(configuration, aliceSecretKey, provider);
  const policyParams = {
    bob: universalBob,
    label,
    threshold,
    shares,
    startDate,
    endDate,
  };
  const policy = await godAlice.grant(
    policyParams
    // includeUrsulas,
    // excludeUrsulas
  );

  const encrypter = new Enrico(policy.policyKey, godAlice.verifyingKey);

  const decrypter = new tDecDecrypter(
    porterUri,
    policy.policyKey,
    policy.encryptedTreasureMap,
    godAlice.verifyingKey,
    bobSecretKey,
    bobSecretKey
  );
  return [encrypter, decrypter, policy];
}

export async function makeTDecDecrypter(
  configLabel: string,
  porterUri: string
): Promise<tDecDecrypter> {
  const config = await getTDecConfig(configLabel);
  return new tDecDecrypter(
    porterUri,
    PublicKey.fromBytes(fromHexString(config['policy_public_key'])),
    EncryptedTreasureMap.fromBytes(fromHexString(config['treasure_map'])),
    PublicKey.fromBytes(fromHexString(config['alice_verifying_key'])),
    SecretKey.fromBytes(fromHexString(config['bob_encrypting_secret'])),
    SecretKey.fromBytes(fromHexString(config['bob_verifying_secret']))
  );
}

export async function makeTDecEncrypter(configLabel: string): Promise<Enrico> {
  const config = await getTDecConfig(configLabel);
  return new Enrico(
    PublicKey.fromBytes(fromHexString(config['policy_public_key'])),
    PublicKey.fromBytes(fromHexString(config['alice_verifying_key']))
  );
}
