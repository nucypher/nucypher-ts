import {
  KeyFrag,
  PublicKey,
  Signature,
  Signer,
  VerifiedKeyFrag,
} from 'umbral-pre';

import { Alice } from '../characters/alice';
import { Bob, RemoteBob } from '../characters/bob';
import { Ursula } from '../characters/porter';
import { keccakDigest } from '../crypto/api';
import {
  EIP712_MESSAGE_SIGNATURE_SIZE,
  ETH_ADDRESS_BYTE_LENGTH,
} from '../crypto/constants';
import { toCanonicalAddress, toChecksumAddress } from '../crypto/utils';
import { MessageKit } from '../kits/message';
import { ChecksumAddress } from '../types';
import {
  decodeVariableLengthMessage,
  encodeVariableLengthMessage,
  fromHexString,
  split,
  toBytes,
  zip,
} from '../utils';
import {
  Deserializer,
  Versioned,
  VersionedDeserializers,
  VersionedParser,
  VersionHandler,
  VersionTuple,
} from '../versioning';

import { HRAC } from './hrac';

export type KFragDestinations = Record<ChecksumAddress, MessageKit>;

export class PublishedTreasureMap {
  constructor(
    public readonly messageKit: MessageKit,
    public destinations: KFragDestinations,
    public threshold: number
  ) {}
}

export class TreasureMap implements Versioned {
  private static readonly BRAND = 'TMap';
  private static readonly VERSION: VersionTuple = [1, 0];

  constructor(
    public readonly threshold: number,
    public readonly destinations: KFragDestinations,
    public readonly hrac: HRAC
  ) {}

  public static async constructByPublisher(
    hrac: HRAC,
    publisher: Alice,
    ursulas: Ursula[],
    verifiedKFrags: VerifiedKeyFrag[],
    threshold: number
  ): Promise<TreasureMap> {
    if (threshold < 1 || threshold > 255) {
      throw Error('The threshold must be between 1 and 255.');
    }

    const nUrsulas = Object.keys(ursulas).length;
    if (nUrsulas < threshold) {
      throw Error(
        `The number of destinations (${nUrsulas}) must be equal or greater than the threshold (${threshold})`
      );
    }

    const destinations = TreasureMap.makeDestinations(
      ursulas,
      verifiedKFrags,
      hrac,
      publisher
    );
    return new TreasureMap(threshold, destinations, hrac);
  }

  public static fromBytes(bytes: Uint8Array): TreasureMap {
    return VersionedParser.fromVersionedBytes(this.getVersionHandler(), bytes);
  }

  protected static getVersionHandler(): VersionHandler {
    const oldVersionDeserializers = (): VersionedDeserializers<Versioned> => {
      return {};
    };
    const currentVersionDeserializer: Deserializer = <T extends Versioned>(
      bytes: Uint8Array
    ): T => {
      const [thresholdBytes, remainder1] = split(bytes, 1);
      const [hracBytes, remainder2] = split(remainder1, HRAC.BYTE_LENGTH);
      const threshold = thresholdBytes.reverse()[0];
      const nodes = this.bytesToNodes(remainder2);
      const hrac = new HRAC(hracBytes);
      return new TreasureMap(threshold, nodes, hrac) as unknown as T;
    };
    return {
      oldVersionDeserializers,
      currentVersionDeserializer,
      brand: this.BRAND,
      version: this.VERSION,
    };
  }

  private static makeDestinations(
    ursulas: Ursula[],
    verifiedKFrags: VerifiedKeyFrag[],
    hrac: HRAC,
    publisher: Alice
  ): KFragDestinations {
    const destinations: KFragDestinations = {};
    zip(ursulas, verifiedKFrags).forEach(([ursula, verifiedKFrag]) => {
      const kFragPayload = AuthorizedKeyFrag.constructByPublisher(
        hrac,
        verifiedKFrag,
        publisher.signer
      ).toBytes();
      const ursulaEncryptingKey = PublicKey.fromBytes(
        fromHexString(ursula.encryptingKey)
      );
      destinations[ursula.checksumAddress] = MessageKit.author(
        ursulaEncryptingKey,
        kFragPayload,
        publisher.signer
      );
    });
    return destinations;
  }

  private static bytesToNodes(bytes: Uint8Array): KFragDestinations {
    const destinations: KFragDestinations = {};
    let bytesRemaining = bytes;
    while (bytesRemaining.length > 0) {
      const [addressBytes, remainder1] = split(
        bytesRemaining,
        ETH_ADDRESS_BYTE_LENGTH
      );
      const [messageKit, remainder2] = decodeVariableLengthMessage(remainder1);
      bytesRemaining = remainder2;
      const address = toChecksumAddress(addressBytes);
      destinations[address] = MessageKit.fromBytes(messageKit);
    }
    return destinations;
  }

  public async encrypt(
    publisher: Alice,
    bob: RemoteBob,
    blockchainSigner?: Signer
  ): Promise<EncryptedTreasureMap> {
    return EncryptedTreasureMap.constructByPublisher(
      this,
      publisher,
      bob,
      blockchainSigner
    );
  }

  private get header(): Uint8Array {
    return VersionedParser.encodeHeader(TreasureMap.BRAND, TreasureMap.VERSION);
  }

  public toBytes(): Uint8Array {
    return new Uint8Array([
      ...this.header,
      // `threshold` must be big-endian
      ...Uint8Array.from([this.threshold]).reverse(),
      ...this.hrac.toBytes(),
      ...TreasureMap.nodesToBytes(this.destinations),
    ]);
  }

  private static nodesToBytes(destinations: KFragDestinations): Uint8Array {
    return Object.entries(destinations)
      .map(
        ([ursulaAddress, encryptedKFrag]) =>
          new Uint8Array([
            ...toCanonicalAddress(ursulaAddress),
            ...encodeVariableLengthMessage(encryptedKFrag.toBytes()),
          ])
      )
      .reduce((previous, next) => new Uint8Array([...previous, ...next]));
  }
}

export class AuthorizedKeyFrag implements Versioned {
  private static readonly WRIT_CHECKSUM_SIZE = 32;
  private static readonly BRAND = 'AKF_';
  private static readonly VERSION: VersionTuple = [1, 0];

  private readonly writ: Uint8Array;

  constructor(
    private readonly hrac: HRAC,
    private readonly kFragChecksum: Uint8Array,
    private readonly writSignature: Signature,
    private readonly kFrag: KeyFrag
  ) {
    this.writ = new Uint8Array([...hrac.toBytes(), ...kFragChecksum]);
  }

  public static constructByPublisher(
    hrac: HRAC,
    verifiedKFrag: VerifiedKeyFrag,
    publisherSigner: Signer
  ): AuthorizedKeyFrag {
    const kFrag = KeyFrag.fromBytes(verifiedKFrag.toBytes());

    const kFragChecksum = AuthorizedKeyFrag.kFragChecksum(kFrag);
    const writ = new Uint8Array([...hrac.toBytes(), ...kFragChecksum]);
    const writSignature = publisherSigner.sign(writ);

    return new AuthorizedKeyFrag(hrac, kFragChecksum, writSignature, kFrag);
  }

  private static kFragChecksum(kFrag: KeyFrag): Uint8Array {
    return keccakDigest(kFrag.toBytes()).slice(
      0,
      AuthorizedKeyFrag.WRIT_CHECKSUM_SIZE
    );
  }

  private get header(): Uint8Array {
    return VersionedParser.encodeHeader(
      AuthorizedKeyFrag.BRAND,
      AuthorizedKeyFrag.VERSION
    );
  }

  public toBytes(): Uint8Array {
    return new Uint8Array([
      ...this.header,
      ...this.writ,
      ...this.writSignature.toBytes(),
      ...this.kFrag.toBytes(),
    ]);
  }
}

export class EncryptedTreasureMap implements Versioned {
  private static readonly BRAND = 'EMap';
  private static readonly VERSION: VersionTuple = [1, 0];
  private readonly EMPTY_BLOCKCHAIN_SIGNATURE = new Uint8Array(
    EIP712_MESSAGE_SIGNATURE_SIZE
  );

  constructor(
    public readonly hrac: HRAC,
    public readonly publicSignature: Signature,
    public readonly encryptedTreasureMap: MessageKit,
    public readonly blockchainSignature?: Signature | null
  ) {}

  public static async constructByPublisher(
    treasureMap: TreasureMap,
    publisher: Alice,
    bob: RemoteBob,
    blockchainSigner?: Signer
  ): Promise<EncryptedTreasureMap> {
    const encryptedTreasureMap = MessageKit.author(
      bob.decryptingKey,
      treasureMap.toBytes(),
      publisher.signer
    );

    const toSign = new Uint8Array([
      ...publisher.verifyingKey.toBytes(),
      ...treasureMap.hrac.toBytes(),
    ]);
    const publicSignature = publisher.signer.sign(toSign);

    const blockchainSignature = blockchainSigner
      ? EncryptedTreasureMap.sign(
          blockchainSigner,
          publicSignature,
          treasureMap.hrac,
          encryptedTreasureMap
        )
      : null;

    return new EncryptedTreasureMap(
      treasureMap.hrac,
      publicSignature,
      encryptedTreasureMap,
      blockchainSignature
    );
  }

  public static sign(
    blockchainSigner: Signer,
    publicSignature: Signature,
    hrac: HRAC,
    encryptedTreasureMap: MessageKit
  ): Signature {
    const payload = new Uint8Array([
      ...publicSignature.toBytes(),
      ...hrac.toBytes(),
      ...encryptedTreasureMap.ciphertext,
    ]);
    return blockchainSigner.sign(payload);
  }

  private get header(): Uint8Array {
    return VersionedParser.encodeHeader(
      EncryptedTreasureMap.BRAND,
      EncryptedTreasureMap.VERSION
    );
  }

  public toBytes(): Uint8Array {
    const signature = this.blockchainSignature
      ? this.blockchainSignature.toBytes()
      : this.EMPTY_BLOCKCHAIN_SIGNATURE;
    return new Uint8Array([
      ...this.header,
      ...this.publicSignature.toBytes(),
      ...this.hrac.toBytes(),
      ...encodeVariableLengthMessage(this.encryptedTreasureMap.toBytes()),
      ...signature,
    ]);
  }

  public decrypt(bob: Bob, publisherVerifyingKey: PublicKey): TreasureMap {
    const bytes = bob.verifyFrom(
      publisherVerifyingKey,
      this.encryptedTreasureMap
    );
    return TreasureMap.fromBytes(bytes);
  }
}

export class RevocationOrder implements Versioned {
  private static readonly BRAND = 'Revo';
  private static readonly VERSION: VersionTuple = [1, 0];
  private PREFIX: Uint8Array = toBytes('REVOKE-');
  private signature?: Signature;

  constructor(
    private ursulaAddress: ChecksumAddress,
    private encryptedKFrag: MessageKit,
    signer?: Signer,
    signature?: Signature
  ) {
    if (!!signature && !!signature) {
      throw Error('Either pass a signer or signature - not both');
    } else if (signer) {
      this.signature = signer.sign(this.payload);
    } else if (signature) {
      this.signature = signature;
    }
  }

  private get header(): Uint8Array {
    return VersionedParser.encodeHeader(
      RevocationOrder.BRAND,
      RevocationOrder.VERSION
    );
  }

  public get payload(): Uint8Array {
    return new Uint8Array([
      ...this.header,
      ...this.PREFIX,
      ...toCanonicalAddress(this.ursulaAddress),
      ...this.encryptedKFrag.toBytes(),
    ]);
  }
}
