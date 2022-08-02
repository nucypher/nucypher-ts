import { SecretKey, VerifiedKeyFrag } from '@nucypher/nucypher-core';
import { ethers } from 'ethers';
import { Ursula } from '../../src/characters/porter';

import {
  generateTDecEntities,
  makeTDecDecrypter,
  makeTDecEncrypter,
} from '../../src/characters/tDec';
import { toBytes } from '../../src/utils';
import {
  mockEncryptTreasureMap,
  mockGenerateKFrags,
  mockGetUrsulas,
  mockMakeTreasureMap,
  mockPublishToBlockchain,
  mockRetrieveCFragsRequest,
  mockUrsulas,
  mockWeb3Provider,
} from '../utils';

describe('threshold decryption', () => {
  const plaintext = toBytes('plaintext-message');

  it('encrypts and decrypts reencrypted message from static config', async () => {
    const encrypter = await makeTDecEncrypter('james-ibex');
    const decrypter = await makeTDecDecrypter(
      'james-ibex',
      'https://porter-ibex.nucypher.community'
    );
    const encryptedMessageKit = encrypter.encryptMessage(plaintext);

    const bobPlaintext = await decrypter.retrieveAndDecrypt([
      encryptedMessageKit,
    ]);
    expect(bobPlaintext[0]).toEqual(plaintext);
  });

  it('encrypts and decrypts reencrypted message from dynamic config', async () => {
    const threshold = 3;
    const shares = 5;
    const label = 'test';
    const startDate = new Date();
    const endDate = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30); // In 30 days
    const aliceSecretKey = SecretKey.random()
    const provider = mockWeb3Provider(aliceSecretKey.toSecretBytes());

    // Setup mocks for `generateTDecEntities`
    const mockedUrsulas = mockUrsulas().slice(0, shares);
    const getUrsulasSpy = mockGetUrsulas(mockedUrsulas);
    const generateKFragsSpy = mockGenerateKFrags();
    const publishToBlockchainSpy = mockPublishToBlockchain();
    const makeTreasureMapSpy = mockMakeTreasureMap();
    const encryptTreasureMapSpy = mockEncryptTreasureMap();

    const [encrypter, decrypter, policy] = await generateTDecEntities(
      threshold,
      shares,
      provider,
      label,
      startDate,
      endDate,
      'https://porter-ibex.nucypher.community',
      aliceSecretKey
    );

    expect(policy.label).toBe(label);
    expect(getUrsulasSpy).toHaveBeenCalled();
    expect(generateKFragsSpy).toHaveBeenCalled();
    expect(publishToBlockchainSpy).toHaveBeenCalled();
    expect(encryptTreasureMapSpy).toHaveBeenCalled();
    expect(makeTreasureMapSpy).toHaveBeenCalled();

    const encryptedMessageKit = encrypter.encryptMessage(plaintext);


    // Setup mocks for `retrieveAndDecrypt`
    const getUrsulasSpy2 = mockGetUrsulas(mockedUrsulas);
    const ursulaAddresses = (makeTreasureMapSpy.mock.calls[0][0] as Ursula[]).map(
      (u) => u.checksumAddress,
    );
    const verifiedKFrags = makeTreasureMapSpy.mock.calls[0][1] as VerifiedKeyFrag[];
    const retrieveCFragsSpy = mockRetrieveCFragsRequest(
      ursulaAddresses,
      verifiedKFrags,
      encryptedMessageKit.capsule,
    );

    const bobPlaintext = await decrypter.retrieveAndDecrypt([
      encryptedMessageKit,
    ]);

    expect(getUrsulasSpy2).toHaveBeenCalled();
    expect(retrieveCFragsSpy).toHaveBeenCalled();
    expect(bobPlaintext[0]).toEqual(plaintext);

  });
});
