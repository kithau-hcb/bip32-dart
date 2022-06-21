import "dart:typed_data";
import "package:pointycastle_hcb/digests/sha512.dart";
import "package:pointycastle_hcb/api.dart" show KeyParameter;
import "package:pointycastle_hcb/macs/hmac.dart";
import "package:pointycastle_hcb/digests/ripemd160.dart";
import "package:pointycastle_hcb/digests/sha256.dart";

final ONE1 = Uint8List.fromList([1]);
final ZERO1 = Uint8List.fromList([0]);

Uint8List hash160(Uint8List buffer) {
  Uint8List _tmp = new SHA256Digest().process(buffer);
  return new RIPEMD160Digest().process(_tmp);
}

Uint8List hmacSHA512(Uint8List key,Uint8List data) {
  final _tmp = new HMac(new SHA512Digest(), 128)..init(new KeyParameter(key));
  return _tmp.process(data);
}

