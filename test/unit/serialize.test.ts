import { MessageKit } from '../../src';
import { AuthorizedKeyFrag, EncryptedKeyFrag, TreasureMap } from '../../src/policies/collections';
import {
  decodeVariableLengthMessage,
  encodeVariableLengthMessage,
  fromHexString,
  split,
  toBytes,
  toHexString,
  zip,
} from '../../src/utils';
import { mockAlice, mockBob, mockTreasureMap } from '../utils';
import { HRAC } from '../../src/policies/hrac';
import { SecretKey } from 'umbral-pre';

const matches = (mk1: MessageKit, mk2: MessageKit) => {
  expect(mk1.capsule.toBytes()).toEqual(mk2.capsule.toBytes());
  expect(mk1.ciphertext).toEqual(mk2.ciphertext);
};

describe('serialization ', () => {
  it('encodes and decodes a hex string', () => {
    const bytes = SecretKey.random().publicKey().toBytes();
    const hexStr = toHexString(bytes);
    const decodedBytes = fromHexString(hexStr);
    expect(decodedBytes).toEqual(bytes);
  });

  it('encodes and decodes a variable length message', () => {
    const msg = new Uint8Array([ 0, 1, 2, 3, 4, 5 ]);

    const encodedMsg = encodeVariableLengthMessage(msg);
    const [ decodedMsg, remainder ] = decodeVariableLengthMessage(encodedMsg);

    expect(decodedMsg).toEqual(msg);
    expect(remainder).toEqual(new Uint8Array());
  });

  it('encodes and decodes a message kit', () => {
    const messageKit = MessageKit.author(
      mockBob().decryptingKey,
      toBytes('fake-message'),
    );

    const encoded = messageKit.toBytes();
    const decoded = MessageKit.fromBytes(encoded);

    matches(decoded, messageKit);
  });

  it('splits bytes', async () => {
    const bytes = new Uint8Array([ 0, 0, 1, 1 ]);

    const [ zeroes, ones ] = split(bytes, 2);
    expect(zeroes).toEqual(new Uint8Array([ 0, 0 ]));
    expect(ones).toEqual(new Uint8Array([ 1, 1 ]));

    const [ all, none ] = split(bytes, bytes.length);
    expect(all).toEqual(bytes);
    expect(none).toEqual(new Uint8Array([]));

    const outOfBounds = () => split(bytes, bytes.length + 1);
    expect(outOfBounds).toThrow();
  });

  it('encodes and decodes kFrag destinations', () => {
    const label = 'fake-label';
    const alice = mockAlice();
    const bob = mockBob();
    const expiration = new Date();
    const { verifiedKFrags } = alice.generateKFrags(bob, label, 1, 1);
    const hrac = HRAC.derive(
      alice.verifyingKey.toBytes(),
      bob.verifyingKey.toBytes(),
      label
    );
    const authorizedKFrag = AuthorizedKeyFrag.constructByPublisher(
      alice.signer,
      hrac,
      verifiedKFrags[0],
      expiration
    );

    const encryptedKFrag = EncryptedKeyFrag.author(
      bob.decryptingKey,
      authorizedKFrag,
    );
    const address = '0x0000000000000000000000000000000000000000';
    const destinations = Object.fromEntries([ [ address, encryptedKFrag ] ]);

    const encoded = TreasureMap['nodesToBytes'](destinations);
    const decoded = TreasureMap['bytesToNodes'](encoded);
    const decodedEncryptedKFrag = Object.values(decoded)[0];

    expect(Object.keys(decoded)[0]).toEqual(address);
    expect(decodedEncryptedKFrag.equals(encryptedKFrag)).toBeTruthy();
  });

  it('encodes and decodes a treasure map', async () => {
    const treasureMap = await mockTreasureMap();

    const encoded = treasureMap.toBytes();
    const decoded = TreasureMap.fromBytes(encoded);

    expect(decoded.threshold).toEqual(treasureMap.threshold);
    expect(decoded.hrac).toEqual(treasureMap.hrac);

    const sortedKeys = zip(Object.keys(treasureMap.destinations).sort(), Object.keys(decoded.destinations).sort());
    sortedKeys.forEach(([ k1, k2 ]) => {
      expect(k1).toEqual(k2);
      const v1 = treasureMap.destinations[k1];
      const v2 = treasureMap.destinations[k2];
      expect(v1.equals(v2));
    });
  });
});
