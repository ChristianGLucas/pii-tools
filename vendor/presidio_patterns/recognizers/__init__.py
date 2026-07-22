# Vendored Microsoft Presidio pattern recognizers (MIT) — see ../NOTICE.md.
# email_recognizer.py is NOT from upstream Presidio (see its own header).
#
# REGISTRY maps entity_type -> (recognizer_class, category, description, example)
# for every recognizer this package wires up. `category` is "generic" (country
# -agnostic) or "us" (United States specific) — mirrors PiiEntity's grouping
# and drives ListSupportedEntities.

from .credit_card_recognizer import CreditCardRecognizer
from .crypto_recognizer import CryptoRecognizer
from .date_recognizer import DateRecognizer
from .email_recognizer import EmailRecognizer
from .iban_recognizer import IbanRecognizer
from .ip_recognizer import IpRecognizer
from .mac_recognizer import MacAddressRecognizer
from .phone_recognizer import PhoneRecognizer
from .url_recognizer import UrlRecognizer

from .aba_routing_recognizer import AbaRoutingRecognizer
from .medical_license_recognizer import MedicalLicenseRecognizer
from .us_bank_recognizer import UsBankRecognizer
from .us_driver_license_recognizer import UsLicenseRecognizer
from .us_itin_recognizer import UsItinRecognizer
from .us_mbi_recognizer import UsMbiRecognizer
from .us_npi_recognizer import UsNpiRecognizer
from .us_passport_recognizer import UsPassportRecognizer
from .us_ssn_recognizer import UsSsnRecognizer

REGISTRY = {
    "EMAIL_ADDRESS": (
        EmailRecognizer,
        "generic",
        "Email address.",
        "jane.doe@example.com",
    ),
    "PHONE_NUMBER": (
        PhoneRecognizer,
        "generic",
        "Phone number, matched region-by-region (US, GB, DE, FR, IL, IN, CA, BR) "
        "via Google's libphonenumber (the `phonenumbers` package).",
        "+1 415-555-2671",
    ),
    "CREDIT_CARD": (
        CreditCardRecognizer,
        "generic",
        "Payment card number (Visa/Mastercard/Amex/etc.), Luhn-checksum validated.",
        "4111 1111 1111 1111",
    ),
    "CRYPTO": (
        CryptoRecognizer,
        "generic",
        "Bitcoin wallet address (P2PKH/P2SH base58check or Bech32/Bech32m), "
        "checksum validated.",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    ),
    "IBAN_CODE": (
        IbanRecognizer,
        "generic",
        "International Bank Account Number, mod-97 checksum and per-country "
        "format validated.",
        "GB82 WEST 1234 5698 7654 32",
    ),
    "IP_ADDRESS": (
        IpRecognizer,
        "generic",
        "IPv4 or IPv6 address, including IPv4-mapped/embedded IPv6 forms.",
        "192.168.1.1",
    ),
    "MAC_ADDRESS": (
        MacAddressRecognizer,
        "generic",
        "MAC (hardware/Ethernet) address — colon-, hyphen-, or Cisco "
        "dot-separated.",
        "00:1A:2B:3C:4D:5E",
    ),
    "URL": (
        UrlRecognizer,
        "generic",
        "Web URL, with or without an explicit http(s):// scheme.",
        "https://example.com/path",
    ),
    "DATE_TIME": (
        DateRecognizer,
        "generic",
        "Calendar date or timestamp in any of ~14 common formats "
        "(ISO 8601, mm/dd/yyyy, dd-MMM-yyyy, etc.) — often a date of birth.",
        "1990-01-15",
    ),
    "US_SSN": (
        UsSsnRecognizer,
        "us",
        "US Social Security Number. Rejects SSA-invalid area/group/serial "
        "combinations and known canonical placeholder numbers.",
        "219-09-1234",
    ),
    "US_ITIN": (
        UsItinRecognizer,
        "us",
        "US Individual Taxpayer Identification Number.",
        "912-73-1234",
    ),
    "US_BANK_NUMBER": (
        UsBankRecognizer,
        "us",
        "US bank account number (8-17 digits) — low-confidence on digits "
        "alone, boosted by nearby banking context words.",
        "12345678901",
    ),
    "US_DRIVER_LICENSE": (
        UsLicenseRecognizer,
        "us",
        "US driver's license number (state formats vary widely; "
        "low-confidence on digits alone).",
        "A1234567",
    ),
    "US_PASSPORT": (
        UsPassportRecognizer,
        "us",
        "US passport number (9 digits, or the newer letter+8-digit format).",
        "912345678",
    ),
    "ABA_ROUTING_NUMBER": (
        AbaRoutingRecognizer,
        "us",
        "American Bankers Association routing transit number, checksum "
        "validated.",
        "021000021",
    ),
    "MEDICAL_LICENSE": (
        MedicalLicenseRecognizer,
        "us",
        "US DEA medical license/registration number, Luhn-family checksum "
        "validated.",
        "AB1234563",
    ),
    "US_NPI": (
        UsNpiRecognizer,
        "us",
        "US National Provider Identifier (healthcare provider ID), "
        "Luhn checksum validated with the CMS \"80840\" prefix.",
        "1234567893",
    ),
    "US_MBI": (
        UsMbiRecognizer,
        "us",
        "US Medicare Beneficiary Identifier.",
        "1EG4-TE5-MK73",
    ),
}

__all__ = ["REGISTRY"]
