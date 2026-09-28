"""Explicit operator actions for signing, testnet anchoring and draft pull requests."""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest='command', required=True)
    keygen = commands.add_parser('keygen'); keygen.add_argument('private_key', type=Path)
    sign = commands.add_parser('sign'); sign.add_argument('report', type=Path); sign.add_argument('--key', required=True); sign.add_argument('--output', required=True, type=Path)
    verify = commands.add_parser('verify'); verify.add_argument('bundle', type=Path); verify.add_argument('--trusted-key', required=True, type=Path)
    anchor = commands.add_parser('anchor'); anchor.add_argument('report', type=Path); anchor.add_argument('--chain-id', type=int, required=True); anchor.add_argument('--publish', action='store_true'); anchor.add_argument('--output', type=Path, required=True)
    check = commands.add_parser('verify-anchor'); check.add_argument('report', type=Path); check.add_argument('receipt', type=Path)
    pr = commands.add_parser('pull-request'); pr.add_argument('report', type=Path); pr.add_argument('--repository', required=True); pr.add_argument('--branch', default=''); pr.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    if args.command == 'keygen':
        from signing import generate_key
        public = generate_key(args.private_key)
        args.private_key.with_suffix('.public.pem').write_bytes(public)
        print('Created signing key and public key. Keep the private key outside repositories and restrict filesystem access.')
    elif args.command == 'verify':
        from signing import verify_bundle
        verify_bundle(args.bundle.read_bytes(), args.trusted_key.read_bytes()); print('Signature and both exported files verified against the trusted key.')
    else:
        report = json.loads(args.report.read_text(encoding='utf-8'))
        if args.command == 'sign':
            from signing import signed_bundle
            args.output.write_bytes(signed_bundle(report, args.key))
        elif args.command == 'anchor':
            if not args.publish:
                parser.error('Anchoring sends a testnet transaction. Add --publish to explicitly submit it.')
            from audit_anchor import anchor_cbom
            receipt = anchor_cbom(report['cbom'], args.chain_id)
            args.output.write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        elif args.command == 'verify-anchor':
            from audit_anchor import verify_anchor
            if not verify_anchor(report['cbom'], json.loads(args.receipt.read_text())):
                raise ValueError('Anchor verification failed.')
            print('Anchor verified.')
        else:
            from github_pr import prepare_pr, publish_pr
            plan = prepare_pr(report, args.repository, args.branch)
            if args.publish:
                print(publish_pr(plan)['html_url'])
            else:
                print(json.dumps({**plan, 'files': [{'path': f['path'], 'diff': f['diff']} for f in plan['files']]}, indent=2))


if __name__ == '__main__':
    main()
