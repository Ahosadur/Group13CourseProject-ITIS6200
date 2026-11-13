
import csv
import hashlib
import random
import secrets
import sqlite3
import urllib.request
from pathlib import Path
import re
# Group personalization
GROUP_NUMBER = 13
PERSONALIZATION_SEED = GROUP_NUMBER % 4

random.seed(GROUP_NUMBER)

# Distribution determined by personalization seed
PASSWORD_DISTRIBUTION = {
    "common": 500,
    "weak_variation": 300,
    "strong": 200
}

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

SOURCE_FILE = DATA_DIR / "seclists.txt"
DATABASE = DATA_DIR / "users.db"
GROUND_TRUTH = DATA_DIR / "ground_truth.csv"

SOURCE_URL = (
    "https://raw.githubusercontent.com/danielmiessler/"
    "SecLists/master/Passwords/Common-Credentials/"
    "10k-most-common.txt"
)


# Get the SecLists password list



def get_common_passwords():
    """
    Download SecLists' 10K common-password list, preserve the original
    source, and remove explicit, sexually explicit, profane, and
    offensive entries without filtering ordinary weak passwords.
    """

    url = (
        "https://raw.githubusercontent.com/danielmiessler/"
        "SecLists/master/Passwords/Common-Credentials/"
        "10k-most-common.txt"
    )

    data_dir = Path(__file__).resolve().parent.parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    source_file = data_dir / "seclists.txt"

    # Download and preserve the unmodified source list.
    with urllib.request.urlopen(url, timeout=30) as response:
        raw_text = response.read().decode("utf-8", errors="replace")

    source_file.write_text(raw_text, encoding="utf-8")

    original_passwords = [
        line.strip()
        for line in raw_text.splitlines()
        if line.strip()
    ]

    # Normalize by removing numbers, punctuation, and symbols.
    # This catches variations such as fuck_me, fuck123, and 1fuck.
    def normalize(value):
        return re.sub(r"[^a-z]", "", value.lower())

    # Explicit words and standalone terms.
    blocked_exact = {
        "pussy", "pussies", "pussys", "pussie", "pussey",
        "fuck", "fucker", "fuckers", "fucking", "fucked",
        "fuckin", "ficken", "shit", "shitty", "shithead",
        "bitch", "bitches", "bitching", "asshole", "assholes",
        "cunt", "cunts", "slut", "sluts", "whore", "whores",
        "dick", "dicks", "cock", "cocks", "penis", "vagina",
        "clitoris", "anal", "porn", "porno", "hentai",
        "nigger", "niggers", "nigga", "niggas",
        "blowjob", "cumshot", "cumming", "cumcum",
        "boobs", "boobies", "tits", "titty", "nipples",
        "horny", "horney", "erotic", "orgasm", "masturbation",
        "bondage", "fetish", "kinky", "voyeur", "naked",
        "pervert", "shemale", "fisting", "dildo",
        "wanker", "wanking", "jackoff", "jerkoff",
        "bollocks", "bugger", "bollock", "bastard",
        "bullshit", "bullocks", "assfuck", "eatshit",
        "deepthroat", "threesome", "threesom", "swinger",
        "spanking", "spankme", "stripper", "poontang",
        "poontang", "creampie", "analsex", "sexsex",
        "sexyman", "sexual", "sexy", "sexx", "sex4me",
        "hotsex", "ilovesex", "bigboobs", "bigballs",
        "bigcock", "bigdick", "bigtits", "bigbooty",
        "bignuts", "dickhead", "cocksucker", "cameltoe",
        "knickers", "knickerless", "panties", "booty",
        "bootys", "assman", "fatass", "dumbass", "badass",
        "jackass", "assword", "assass", "assfuck",
        "butthead", "buttman", "butts", "suckit", "suckme",
        "sucks", "sucking", "lickme", "lickit", "licking",
        "eatpussy", "wetpussy", "pussycat", "pussy69",
        "fuckme", "fuckyou", "fuckoff", "fuckit",
        "fuckface", "fuckfuck", "fuckers", "fuck_inside",
        "blowme", "biteme", "suckers", "horndog",
        "hardon", "boner", "horny", "balls", "snatch",
        "shagging", "shag", "fart", "poop", "poopie",
        "pooper", "poopoo", "dookie", "dildo",
        "nookie", "hustler", "hooker", "prostitute",
        "strip", "smut", "voyeur", "nasty",
    }

    # Explicit compounds. These are checked as substrings because
    # users commonly add names, numbers, or other characters around them.
    blocked_compounds = {
        "fuck", "shit", "bitch", "asshole", "cunt",
        "pussy", "cocksucker", "bigdick", "mydick",
        "dickhead", "bigcock", "bigboobs", "bigtits",
        "bigballs", "bigbooty", "bignuts", "cameltoe",
        "knickerless", "blowjob", "cumshot", "creampie",
        "deepthroat", "analsex", "eatpussy", "wetpussy",
        "fuckface", "fuckoff", "fuckyou", "fuckme",
        "fuckit", "fuckin", "fuck_inside", "assfuck",
        "dumbass", "fatass", "jackass", "badass",
        "butthead", "buttman", "bullshit", "eatshit",
        "cumming", "cocksucker", "jerkoff", "jackoff",
        "lickme", "lickit", "suckme", "suckit",
        "spankme", "sex4me", "ilovesex", "hotsex",
        "sexyman", "sexsex", "sexual", "nigger",
        "shemale", "wanker", "wanking", "poontang",
        "pussies", "pussys", "pussie", "pussey",
        "blowme", "horndog", "hardon", "assman",
        "assword", "assass", "bigbooty", "bigballs",
    }

    # Terms that should remain even if a substring might look suspicious.
    # These are ordinary words or recognizable common-password entries.
    allowed_words = {
        "password", "password1", "passw0rd", "pass",
        "passion", "passenger", "passage", "compass",
        "class", "classic", "classroom", "arsenal",
        "assassin", "assistant", "assess",
        "hello", "hello1", "hello123",
        "butter", "butterfly", "butterfl",
        "titan", "titanic", "titans", "titleist",
        "hellfire", "pussycat",
        "cockroach", "cockpit",
        "bass", "bassman",
        "black", "asian", "lesbian",
    }

    def is_inappropriate(password):
        normalized = normalize(password)

        if not normalized:
            return False

        if normalized in allowed_words:
            return False

        if normalized in blocked_exact:
            return True

        # Catch explicit terms embedded in compounds and variations.
        if any(term in normalized for term in blocked_compounds):
            return True

        # Additional exact-root checks for common suffix variations.
        # This does not use broad substrings such as "ass" or "tit".
        suffix_roots = (
            "pussy", "fuck", "bitch", "shit", "cunt",
            "nigger", "nigga", "whore", "slut",
            "penis", "vagina", "porn", "porno",
            "hentai", "wanker", "bollock",
        )

        for root in suffix_roots:
            if normalized.startswith(root):
                return True

        return False

    filtered_passwords = [
        password
        for password in original_passwords
        if not is_inappropriate(password)
    ]

    removed_count = len(original_passwords) - len(filtered_passwords)

    print(f"Original SecLists entries: {len(original_passwords)}")
    print(f"Filtered inappropriate entries: {removed_count}")
    print(f"Remaining usable entries: {len(filtered_passwords)}")

    if len(filtered_passwords) < 500:
        raise ValueError(
            "Not enough passwords remain after filtering. "
            "Review the filter before generating the dataset."
        )

    # Verify that ordinary weak/common passwords are still available.
    required_examples = {
        "password", "123456", "qwerty", "dragon",
        "baseball", "football", "letmein", "monkey",
        "hello", "arsenal", "classic", "titanic",
    }

    remaining_lower = {
        password.lower() for password in filtered_passwords
    }

    missing_examples = required_examples - remaining_lower

    if missing_examples:
        raise ValueError(
            "The filter unexpectedly removed ordinary passwords: "
            + ", ".join(sorted(missing_examples))
        )

    return filtered_passwords



# Create weak variations of common passwords
def create_weak_password(password):

    changes = [
        lambda p: p + "123",
        lambda p: p + "2025",
        lambda p: p + "!",
        lambda p: p + "@123",
        lambda p: p.capitalize() + "!",
        lambda p: p + "2026"
    ]

    return random.choice(changes)(password)


# Generate a random strong password
def create_strong_password():

    characters = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*"
    )

    return "".join(
        secrets.choice(characters) for _ in range(20)
    )


# Generate the 1,000 synthetic accounts
def generate_users(common_passwords):

    users = []

    common_count = PASSWORD_DISTRIBUTION["common"]
    weak_count = PASSWORD_DISTRIBUTION["weak_variation"]
    strong_count = PASSWORD_DISTRIBUTION["strong"]

    for i in range(common_count):
        users.append({
            "username": f"user{i + 1:04d}",
            "password": random.choice(common_passwords),
            "category": "common"
        })

    for i in range(weak_count):
        base = random.choice(common_passwords)
        users.append({
            "username": f"user{i + common_count + 1:04d}",
            "password": create_weak_password(base),
            "category": "weak_variation"
        })

    for i in range(strong_count):
        users.append({
            "username": f"user{i + common_count + weak_count + 1:04d}",
            "password": create_strong_password(),
            "category": "strong"
        })

    random.shuffle(users)

    return users


# Create the initial database using legacy MD5
def create_database(users):

    connection = sqlite3.connect(DATABASE)

    connection.execute("DROP TABLE IF EXISTS users")

    connection.execute("""
        CREATE TABLE users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            hash_scheme TEXT NOT NULL,
            migration_status TEXT NOT NULL,
            migrated_at TEXT
        )
    """)

    for user in users:

        md5_hash = hashlib.md5(
            user["password"].encode("utf-8")
        ).hexdigest()

        connection.execute("""
            INSERT INTO users (
                username,
                password_hash,
                hash_scheme,
                migration_status
            )
            VALUES (?, ?, ?, ?)
        """, (
            user["username"],
            md5_hash,
            "md5",
            "pending"
        ))

    connection.commit()
    connection.close()


# Keep original passwords separately for testing
def save_ground_truth(users):

    with open(GROUND_TRUTH, "w", newline="", encoding="utf-8") as file:

        writer = csv.DictWriter(
            file,
            fieldnames=["username", "password", "category"]
        )

        writer.writeheader()
        writer.writerows(users)


# Run the dataset generation
def main():

    DATA_DIR.mkdir(exist_ok=True)

    common_passwords = get_common_passwords()

    if len(common_passwords) < 500:
        raise ValueError("Not enough passwords in the source list.")

    users = generate_users(common_passwords)

    create_database(users)
    save_ground_truth(users)

    print("\nDataset created successfully!")
    print("Total accounts: 1000")
    print("Common passwords: 500")
    print("Weak variations: 300")
    print("Strong passwords: 200")
    print("\nAll accounts initially use unsalted MD5.")


if __name__ == "__main__":
    main()
