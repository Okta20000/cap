from pathlib import Path
from loguru import logger
from discord.register import register

def main():
    emails = [l.strip() for l in Path("emails.txt").read_text().splitlines() if l.strip()]
    if not emails:
        logger.error("no emails in emails.txt")
        return

    for email in emails:
        result = register(email)
        if result:
            Path("accounts.txt").open("a").write(
                f"{result['email']}:{result['password']}:{result['token']}\n"
            )

if __name__ == "__main__":
    main()