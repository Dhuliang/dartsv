import 'package:dartsv/src/exceptions.dart';
import 'package:dartsv/src/script/opcodes.dart';
import 'package:dartsv/src/transaction/signed_unlock_builder.dart';
import 'package:hex/hex.dart';
import 'package:sprintf/sprintf.dart';

import '../../dartsv.dart';

/// ** P2PKH locking Script ***
mixin P2PKHLockBadgeMixin on _P2PKHLockBadgeBuilder
    implements LockingScriptBuilder {
  @override
  SVScript getScriptPubkey() {
    String destAddress;
    int addressLength;
    if (address != null) {
      destAddress = address.address; //hash160(pubkey) aka pubkeyHash

      addressLength = HEX.decode(destAddress).length;

      //FIXME: Another hack. For some reason some addresses don't have proper ripemd160 hashes of the hex value. Fix later !
      if (addressLength == 33) {
        addressLength = 20;
        destAddress = HEX.encode(hash160(HEX.decode(destAddress)));
      }
    } else if (pubkeyHash != null) {
      addressLength = pubkeyHash.length;
      destAddress = HEX.encode(pubkeyHash);
    } else {
      return SVScript(); //return empty script if no pubkeyHash or Address
    }

    var scriptString = sprintf(
        "OP_DUP OP_HASH160 %s 0x%s OP_EQUALVERIFY OP_CHECKSIG",
        [addressLength, destAddress]);

    return SVScript.fromString(scriptString);
  }
}

abstract class _P2PKHLockBadgeBuilder implements LockingScriptBuilder {
  Address address;
  List<int> pubkeyHash;

  _P2PKHLockBadgeBuilder(this.address);

  _P2PKHLockBadgeBuilder.fromPublicKey(SVPublicKey publicKey,
      {NetworkType networkType = NetworkType.MAIN}) {
    address = publicKey.toAddress(networkType);
    pubkeyHash = HEX.decode(address.pubkeyHash160);
  }

  @override
  void fromScript(SVScript script) {
    if (script != null && script.buffer != null) {
      var chunkList = script.chunks;

      if (chunkList.length != 5) {
        throw ScriptException(
            "Wrong number of data elements for P2PKH ScriptPubkey");
      }

      if (chunkList[2].len != 20) {
        throw ScriptException("Signature and Public Key values are malformed");
      }

      if (!(chunkList[0].opcodenum == OpCodes.OP_DUP &&
          chunkList[1].opcodenum == OpCodes.OP_HASH160 &&
          chunkList[3].opcodenum == OpCodes.OP_EQUALVERIFY &&
          chunkList[4].opcodenum == OpCodes.OP_CHECKSIG)) {
        throw ScriptException(
            "Malformed P2PKH ScriptPubkey script. Mismatched OP_CODES.");
      }

      pubkeyHash = chunkList[2].buf;
    } else {
      throw ScriptException("Invalid Script or Malformed Script.");
    }
  }
}

class P2PKHLockBadgeBuilder extends _P2PKHLockBadgeBuilder
    with P2PKHLockBadgeMixin {
  P2PKHLockBadgeBuilder(Address address) : super(address);
  P2PKHLockBadgeBuilder.fromPublicKey(SVPublicKey publicKey,
      {NetworkType networkType = NetworkType.MAIN})
      : super.fromPublicKey(publicKey, networkType: networkType);
}

/// ** P2PKH unlocking Script (scriptSig / Input script) ***
mixin P2PKHUnlockBadgeMixin on _P2PKHUnlockBadgeBuilder
    implements UnlockingScriptBuilder {
  /// The developer is required to perform their own error handling when
  /// implementing this method. You should consider throwing an exception if
  /// your Signature value is null, because that guards you against trying to
  /// serialize an unsigned TX.
  @override
  SVScript getScriptSig() {
    if (signatures == null || signatures.isEmpty || signerPubkey == null)
      return SVScript();

    var pubKeySize = HEX.decode(signerPubkey.toString()).length;
    var signatureSize = HEX.decode(signatures[0].toTxFormat()).length;
    var scriptString =
        sprintf("%s 0x%s", [signatureSize, signatures[0].toTxFormat()]);

    var scriptStringFinal = unlockingScriptHexs.join(scriptString);

    return SVScript.fromString(scriptStringFinal);
  }
}

abstract class _P2PKHUnlockBadgeBuilder extends SignedUnlockBuilder
    implements UnlockingScriptBuilder {
  SVPublicKey signerPubkey;
  List<String> unlockingScriptHexs;

  @override
  List<SVSignature> signatures = <SVSignature>[];

  //The signature *must* be injected later, because of the way SIGHASH works
  //Hence the contract enforced by SignedUnlockBuilder
  _P2PKHUnlockBadgeBuilder(this.signerPubkey, this.unlockingScriptHexs);

  //Allow the scriptSig to be initialized from Script.
  // Parse signature and signerPubkey

  @override
  void fromScript(SVScript script) {
    if (script != null && script.buffer != null) {
      var chunkList = script.chunks;

      if (chunkList.length != 2) {
        throw ScriptException(
            "Wrong number of data elements for P2PKH ScriptSig");
      }

      //removing for now... we might have compressed pubkey
      // if (chunkList[0].len != 73 && chunkList[1].len != 65){
      //   throw ScriptException("Signature and Public Key values are malformed");
      // }

      var sig = chunkList[0].buf;
      var pubKey = chunkList[1].buf;

      signerPubkey = SVPublicKey.fromHex(HEX.encode(pubKey));
      signatures.add(SVSignature.fromTxFormat(HEX.encode(sig)));
    } else {
      throw ScriptException("Invalid Script or Malformed Script.");
    }
  }

  SVScript get scriptSig => getScriptSig();
}

//FIXME: We need to figure out a way to enforce the requirement of a "fromScript()"
// constructor here. Dunno if it's possible
class P2PKHUnlockBadgeBuilder extends _P2PKHUnlockBadgeBuilder
    with P2PKHUnlockBadgeMixin {
  //Expect the Signature to be injected after the fact. Input Signing is a
  //weird one.
  P2PKHUnlockBadgeBuilder(
      SVPublicKey signerPubkey, List<String> unlockingScriptHexs)
      : super(signerPubkey, unlockingScriptHexs);
}
