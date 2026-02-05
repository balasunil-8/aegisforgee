"""Small CLI to generate CTF challenges for PentestLab."""
import argparse
from ctf_manager import generate_challenge


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--kind', choices=['crypto', 'stego', 'forensics', 'misc'], required=True)
    p.add_argument('--title', required=True)
    args = p.parse_args()

    meta = generate_challenge(args.kind, args.title)
    print('Created', meta['id'])


if __name__ == '__main__':
    main()
