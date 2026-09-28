class HCaptchaError(Exception):
    """Base hCaptcha error."""


class KeyFetchError(HCaptchaError):
    """Could not obtain AES master keys for the current build."""


class BuildRotatedError(HCaptchaError):
    """Build hash changed mid-session — refetch keys and retry."""


class PowError(HCaptchaError):
    """Proof-of-work solving failed."""


class ChallengeSolveError(HCaptchaError):
    """Visual challenge could not be solved."""


class TokenExtractionError(HCaptchaError):
    """Final P1_ token not present in response."""