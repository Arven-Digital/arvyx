"""Verify the reviewed Paperclip provenance before allowing missing inline notices."""
import hashlib
import json
from pathlib import Path, PurePosixPath

PROVENANCE = 'frontends/paperclip/vendor/provenance.json'
# Fix-02 changed only the manifest representation to path/sha256 records.
# Its frozen inventory retains exactly the same 396 upstream byte hashes.
PROVENANCE_SHA256 = '9c52dc08384aa1dd58ea1fa03cff257bb86dbc4e13a37d5f6ba34d538f8922f9'
PIN = 'efce9356b553a08f77a5877bb0ceac68d2cc4ad8'
# Supplemental byte pins are generated from the reviewed upstream checkout and
# format-constrained local npm metadata. No wildcard, extension or directory bypass.
SUPPLEMENTAL = {'frontends/paperclip/package.json': '733179d96f5d1d90bb740935bbc43a31c6bafb39347da034d98e572faa6815d0', 'frontends/paperclip/package-lock.json': 'ffe4f31d1c9bc3ed99b207826e2b64fb7777a3a5acd8e60bd77a4ce274a689b9', 'frontends/paperclip/vendor/LICENSE': '7f8a27f0979bded50e240caa8c8c29f3088ddf87032cb83e5a9732bff91d18b4', 'frontends/paperclip/public/fonts/InterVariable.woff2': '693b77d4f32ee9b8bfc995589b5fad5e99adf2832738661f5402f9978429a8e3', 'frontends/paperclip/public/fonts/InterVariable-Italic.woff2': 'e564f652916db6c139570fefb9524a77c4d48f30c92928de9db19b6b5c7a262a', 'frontends/paperclip/public/fonts/NOTICE.md': '23d37fbe6c5013788e64e170677a5f6a441997e0f0dfe8e0f409cbd75df7466a'}


# Patch-only tooling updates resolve the recorded npm advisories; upstream bytes
# above remain unchanged. These two exact local-format pins supersede the base.
SUPPLEMENTAL.update({
    'frontends/paperclip/package.json': '5643c385e9774a1654380e9a05186a36a88e128e2de46b74e285105bd93dcbf9',
    'frontends/paperclip/package-lock.json': '0bb6d119390a6392d06534d32a593a760bb1df7f72c1d1502107b35a7337a509',
})


# Local Arvyx metadata: explicit name plus pinned TypeScript/type tooling already
# present in the candidate. This is a notice-only pin, not security clearance.
SUPPLEMENTAL.update({
    'frontends/paperclip/package.json': '0ab517da9a027c5a66585e3ffb9340170bb2c9b148a2ba2c33e2dfa2c874c6a4',
    'frontends/paperclip/package-lock.json': '927a0c6892b4ce952396856f6cb8dd0f3adc7a94310b836c870166d38c3c5d4d',
})


# Public candidate review 2026-11-02: the frontend package is named for what it
# is (`arvyx-control-room`); dependencies and lockfile contents are unchanged.
SUPPLEMENTAL.update({
    'frontends/paperclip/package.json': 'd6de69335ad94a9497f9e43c5becc1961fe639956e36b940d4114677272433e1',
    'frontends/paperclip/package-lock.json': 'd32852b10b6af91b97e1469a9a21a95435ee192747a1cd16fc418951c4b9434c',
})


# Reviewed local patches to upstream vendor files (review 2026-10-30, recorded in
# the maintainers' packaging-gates record). Each entry binds the
# exact upstream digest recorded in provenance.json to the exact patched digest.
# The upstream inventory above is unchanged; a patch never adds a file, and any
# other byte change, or a provenance digest that no longer matches, fails.
LOCAL_PATCHES = {
    'api/client.ts': ('34fc2c3d4c7d01217e3c6539e244b8bdb45a1f4135a629446970b31c2dfec573',
        'c7b004885bc488061c69e8cc9b1f003c1393f8cfb0af795a13cf8fe0e937614b',
        'G16: computed headers are applied after ...init'),
    'shared/app-definitions-url.test.ts': ('e6ee9c5ce37bd987d57bb3a425f25ea2998e1ed34b77f26044e44418ddc82fcf',
        'f96f72e2287d0b4ac0d5f3625ed5ab63a6e6325f7094de7e6d099392483fb288',
        'CodeQL js/incomplete-sanitization: the example URL replaces every wildcard (replaceAll)'),
    'shared/app-definitions.ts': ('2cc7b01a556f691322d5bb5b928a6c3bfb040b98907ca7423762fdb8fa28e42b',
        '69c35a3b9693dc23f3791aa08573d70bfe956dc3eecda2b0ba90842b493adf74',
        'S46/G18: structured host/path matching; no credentials; storeDomain shape'),
    'shared/company-import-transfer.ts': ('7954318ecd3f9c2a4889438612bc1a63db9cae4f6f78e481fa779153e434f1f6',
        'd1f782a200b276b604a731e6d6d2ad258ba5563afbd3233c27c9d378a0588b12',
        'declared parts must be unique contiguous ranges matching totalBytes'),
    'shared/config-schema.ts': ('e598e3b5c6e16a9c0bc43e295f5d079b2df572c294c0e1215ecb9003572cdf56',
        '4a0097610d6b3bd129f5030a8acba4dd5194ab63612b3638ea35cf5e04f0304b',
        'unwrap ZodNullable/ZodPrefault (zod 4.6.7)'),
    'shared/connection-routing.ts': ('2bf3c0b22f59515716cf75ba4d597521e18619e6919b286c31f8cd1778d6af0f',
        'ed3fd5fae631fecf8c4158dae78a3bf316926855d0fa6c17afabf16380815614',
        'G21: common-word service names require a multi-word phrase'),
    'shared/document-anchors.ts': ('19929bdbbe1e07177efb4fd7ba301b2a94c886f0ea2afc3db76329b7998b661f',
        '495183414361023cf8f0dcdf7a5301930a0a51a40aab10b0879410c8aafa67e5',
        'S48/G24: escapes and paired delimiters; recursion depth 32'),
    'shared/environment-custom-images.ts': ('a8932f77d398386d386f4ca5ca022d9b9759a9d81d110aa2909f6d3a884ea4fa',
        '889d300a762da9cf4c3950d2fbedfa61662978dc78ea1a751e498529eb6b240f',
        '*Redacted keys bypass only as booleans; port keys redacted'),
    'shared/frontmatter.ts': ('879e3ee0555b9cb59a62e79cc3f0f7d3bb38b46bf312aa9f26827ef28c1fac09',
        'eac9cfa85e79024d5d5612be3d4f1d5b99431027291bb2d44c9140aa82a08283',
        'leading-whitespace values serialized as quoted scalars'),
    'shared/humanize-connection.ts': ('4de3a5913f24a524b5bd279b3f1078a31598e0b7c6ec3ccc702a58663b55720e',
        'eeb29461901e6898a5873a3c2cc1716f5eeed2f0883edebe8ecd130d273d73b9',
        'hint exposes only http(s) host'),
    'shared/portability-zip.test.ts': ('7d48436c195120e9717d9ee1b99f10c808c976088b6c2306cbfad3990053893a',
        'af0a7f4cd24093cd524d4c8d0cc50a071610b013b12ea1a795fd5d916c9786c4',
        'S50 regression tests; stricter-location assertions'),
    'shared/portability-zip.ts': ('b5860afd9ab301fb9cd44f3b3799c28d6fe6297fc891ebbe330b4b62bc53bd4e',
        '7eec130940d830a874cf88b3d03df14bd8ec1c4450b542de915251f92eb3801d',
        'S50: path safety, CRC/size, local/central agreement, bounded expansion'),
    'shared/runtime-exposure/loopback-bind.test.ts': ('251e02f266eb3a5a88eb905b79a4766bf32ed1881e795407d871f84dcbf3c8a9',
        '45da67859c82f28b00c4c68530582c44b69068246e7d2ced00c655a6a74ef107',
        'assert refusal of ambiguous valueless --bind'),
    'shared/runtime-exposure/loopback-bind.ts': ('92e3afb3b6178b7c7052893aa30715f68cf34383fa702a4d64f0a33b718a6a56',
        '5731ad8c74a3a675a6f778138914960862eb8f74b78e7258cf466ba165f1c5dc',
        'argv-only parsing; ambiguous bind refused'),
    'shared/telemetry/client.test.ts': ('5c36325b42226ccd2a58f28efb5b7c43b0608e8d1781850dc359be42f2676cae',
        'eab1a7fe1ed84f713d668e5d241e9cd84f27aa8ba0ae49c62e7945a9699e5840',
        '#52: identical occurrences get distinct ids'),
    'shared/telemetry/client.ts': ('e56c8c28be0c5f7675aff6f1049c065412897e6cf2717c057c3f790761080235',
        'cf2bcde13bb0b0158b1abfd58b5cc634719becaeb5dacba0c294dbd21be23a15',
        '#52: per-occurrence batch ids; response stream released'),
    'shared/telemetry/state.ts': ('79ac266569c76941d037786f7a22900eac67b633eabbc61e6f7127659b2787c5',
        '954b7f303c0c1a2dc51b062e47ade80a09c150884c82155387ba8a6a270feab8',
        'private no-follow state file; atomic create; strict shape'),
    'shared/validators/adapter-auth-session.ts': ('402f0d4c9c15f94367808c3f98a8df89e19fa42c86328b74e50aa434b78a2a55',
        'a2914a8c14090425540fd2df0b7480d7c1ee6f223b57220d03766ce177a744cd',
        '#54: codexAccountBinding matches exported type'),
    'shared/validators/agent.ts': ('130f8a19a40586f07a7421687b6c0b8663aab5f0c46df27d7bbbac0d3b88a3e4',
        '74301488b0eeb5d014b12e2f2c6c8ad1075e4ad7402d1838b753a23579107417',
        'invalid key scope refused instead of downgraded to standard'),
    'shared/validators/email.ts': ('b00d97c24f20746c1af29479691f51fd700b8aefc1054563422ace0b5c275c91',
        '0183b5ec1c7086fb6268aba6e8b2d7fd8dd2c5300e25a65c99b2fdfd8bbdf788',
        'G29: domain shape; header-delimiter refusal in Message-ID'),
    'shared/validators/issue.ts': ('e324c31a04537421e6b54a5863d852bf92b9636d598bd193f912ce667e8f5741',
        'a44cf6ebdb120976a4e7f771de0d82fb6169dec68abf450b43839cbf8fa71ad5',
        '#55: answers limit matches the 64-question limit'),
    'shared/validators/plugin.ts': ('744d2686172923ea973d3654d9d7342a07d78e3b0a715a2b2b14c33218f5f7e3',
        'b4ad89a00d45f558ab5c20baa7d3de1222a7756147883c5e8b6d78de2f6dcdd0',
        'drive/control-char paths refused; navigate targets host routes only'),
    'shared/validators/skill-policy.ts': ('bf0b179ebeb60cde8a4f2c4f6b2c84fe2077862a6d290e1a9bbe24547a1b16dc',
        'b1c26b1f9cd6f7a8c9aaaaaa2b2a2b11b82f189ec7a5ded480ffe57ecbc0dac6',
        'normalized locator keeps explicit port'),
    'shared/workspace-commands.ts': ('edc160feae648ca06305b1ffe5a110b9ceac2787a4f1fb7e3aedb05f825e7a47',
        '29d1b6fe438a138a40e7fc2359343ced02270e4acfdf7e36a298ceb028cd26af',
        'fallback command ids stay unique'),
    'shared/worktree-port-registry.ts': ('9c6a9cc048b0b683063289611bef810e49342394c08e235bc7fc02e45562c88d',
        '978a64a79a9b687da6799dc6d05daeb4e37bbd7a96b55f7e9c6fcfef15c249c0',
        'namespace guard; unknown process identity never reclaimed'),
}


def verified_notice_exemptions(repo: Path, classifications):
    def read(path):
        full = repo / path
        if any(parent.is_symlink() for parent in [full, *full.parents] if parent != repo.parent):
            raise ValueError(f'symlink in immutable private path: {path}')
        return full.read_bytes()

    raw = read(PROVENANCE)
    if hashlib.sha256(raw).hexdigest() != PROVENANCE_SHA256:
        raise ValueError('Paperclip provenance digest changed')
    data = json.loads(raw)
    if data['commit'] != PIN or len(data['files']) != 396:
        raise ValueError('Paperclip provenance pin/count changed')
    pins = {PROVENANCE: PROVENANCE_SHA256, **SUPPLEMENTAL}
    patched = set()
    for entry in data['files']:
        rel, digest = entry['path'], entry['sha256']
        parts = PurePosixPath(rel)
        if parts.is_absolute() or '..' in parts.parts or str(parts) != rel:
            raise ValueError('unsafe upstream provenance path')
        if rel in LOCAL_PATCHES:
            upstream, local, _reason = LOCAL_PATCHES[rel]
            if digest != upstream:
                raise ValueError(f'local patch is not bound to the recorded upstream bytes: {rel}')
            digest = local
            patched.add(rel)
        pins['frontends/paperclip/vendor/' + rel] = digest
    if patched != set(LOCAL_PATCHES):
        raise ValueError('local patch names a file outside the upstream inventory')
    for path, digest in pins.items():
        # Byte pins hold whatever the classification is; only private-only paths
        # need the notice exemption (public-approved vendored files carry none and
        # are exported as reviewed upstream bytes under their own licence).
        if hashlib.sha256(read(path)).hexdigest() != digest:
            raise ValueError(f'immutable private bytes changed: {path}')
    return {path: 'Reviewed exact bytes; private export restriction unchanged'
            for path in pins if classifications.get(path) == 'private-only'}
