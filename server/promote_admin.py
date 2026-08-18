
import sys

import db


def main():
    if len(sys.argv) < 2:
        print("usage: python3 promote_admin.py <account_id> [--revoke]")
        sys.exit(1)

    account_id = sys.argv[1]
    revoke = "--revoke" in sys.argv[2:]

    if db.get_account_pubkey(account_id) is None:
        print(f"error: '{account_id}' is not enrolled yet -- register it first")
        sys.exit(1)

    db.set_admin(account_id, admin=not revoke)
    print(f"{'revoked' if revoke else 'granted'} admin for account '{account_id}'")


if __name__ == "__main__":
    main()
