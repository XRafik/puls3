import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:puls3_flutter/src/auth/auth_config.dart';
import 'package:stellar_flutter_sdk/stellar_flutter_sdk.dart';

void main() {
  const serverKey = 'GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57';
  const otherKey = 'GD6ROJBYLKQMOW3E7N4M2YBPUHMZD7PL65VRHRMO24BOVSBV5H3BQRSL';
  const testnet = 'Test SDF Network ; September 2015';

  String configWith(Map<String, Object?>? auth) => jsonEncode({
    'apiUrl': 'http://localhost:8080',
    'auth': ?auth,
  });

  final bundled = configWith({
    'serverSigningKey': serverKey,
    'homeDomain': 'puls3.app',
    'webAuthDomain': 'auth.puls3.app',
    'networkPassphrase': testnet,
  });

  group('AuthConfig.parse', () {
    test('reads the four public values from the auth block', () {
      final config = AuthConfig.parse(bundled, overrides: const {});

      expect(config.serverSigningKey, serverKey);
      expect(config.homeDomain, 'puls3.app');
      expect(config.webAuthDomain, 'auth.puls3.app');
      expect(config.networkPassphrase, testnet);
    });

    test('a missing auth block fails closed', () {
      expect(
        () => AuthConfig.parse(configWith(null), overrides: const {}),
        throwsA(
          isA<AuthConfigUnavailable>().having(
            (e) => e.missing,
            'missing',
            containsAll([
              'serverSigningKey',
              'homeDomain',
              'webAuthDomain',
              'networkPassphrase',
            ]),
          ),
        ),
      );
    });

    test('a blank field fails closed and names it', () {
      final config = configWith({
        'serverSigningKey': serverKey,
        'homeDomain': '  ',
        'webAuthDomain': 'auth.puls3.app',
        'networkPassphrase': testnet,
      });
      expect(
        () => AuthConfig.parse(config, overrides: const {}),
        throwsA(
          isA<AuthConfigUnavailable>().having(
            (e) => e.missing,
            'missing',
            ['homeDomain'],
          ),
        ),
      );
    });

    test('a secret seed is refused and never echoed', () {
      final secret = KeyPair.random().secretSeed;
      final config = configWith({
        'serverSigningKey': secret,
        'homeDomain': 'puls3.app',
        'webAuthDomain': 'auth.puls3.app',
        'networkPassphrase': testnet,
      });
      expect(
        () => AuthConfig.parse(config, overrides: const {}),
        throwsA(
          isA<AuthConfigUnavailable>().having(
            (e) => e.toString(),
            'message',
            allOf(contains('serverSigningKey'), isNot(contains(secret))),
          ),
        ),
      );
    });

    test('dart-define overrides win over the bundled file', () {
      final config = AuthConfig.parse(
        bundled,
        overrides: const {
          AuthConfig.serverSigningKeyDefine: otherKey,
          AuthConfig.homeDomainDefine: 'staging.puls3.app',
          AuthConfig.webAuthDomainDefine: 'auth.staging.puls3.app',
          AuthConfig.networkPassphraseDefine: 'Other network',
        },
      );

      expect(config.serverSigningKey, otherKey);
      expect(config.homeDomain, 'staging.puls3.app');
      expect(config.webAuthDomain, 'auth.staging.puls3.app');
      expect(config.networkPassphrase, 'Other network');
    });

    test('overrides fill a missing auth block; blank ones are ignored', () {
      final config = AuthConfig.parse(
        configWith(null),
        overrides: const {
          AuthConfig.serverSigningKeyDefine: serverKey,
          AuthConfig.homeDomainDefine: 'puls3.app',
          AuthConfig.webAuthDomainDefine: 'auth.puls3.app',
          AuthConfig.networkPassphraseDefine: testnet,
        },
      );
      expect(config.homeDomain, 'puls3.app');

      final kept = AuthConfig.parse(
        bundled,
        overrides: const {AuthConfig.homeDomainDefine: ' '},
      );
      expect(kept.homeDomain, 'puls3.app');
    });

    test('defaults to the compile-time defines (unset in tests)', () {
      expect(authConfigDefines.values.every((v) => v.isEmpty), isTrue);
      expect(AuthConfig.parse(bundled).serverSigningKey, serverKey);
    });

    test('the bundled assets/config.json carries a public auth block', () {
      final asset = File('assets/config.json').readAsStringSync();
      final config = AuthConfig.parse(asset, overrides: const {});

      expect(config.serverSigningKey, startsWith('G'));
      expect(config.networkPassphrase, testnet);
      expect(asset, isNot(contains('"S')));
    });
  });
}
