from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from harica_client.cache import CacheSnapshot
from harica_client.certificate_stats import (
    expirations_report,
    normalize_certificate,
    owners_report,
    quality_report,
    summary_report,
    summary_rows,
)


class CertificateStatsTests(unittest.TestCase):
    NOW = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)

    def _record(
        self,
        serial: str,
        *,
        status: str = "valid",
        valid_to: datetime | str | None = None,
        user: str = "Mario Rossi",
        email: str = "mario@example.org",
        friendly_name: str = "Portale",
        cn: str = "portal.example.org",
        is_revoked: bool | None = False,
        revoked_at: datetime | str | None = None,
    ) -> dict[str, object]:
        def date_value(value: datetime | str | None) -> str | None:
            if isinstance(value, datetime):
                return value.isoformat()
            return value

        return {
            "serial": serial,
            "status": status,
            "validFrom": (self.NOW - timedelta(days=10)).isoformat(),
            "validTo": date_value(valid_to or self.NOW + timedelta(days=100)),
            "isRevoked": is_revoked,
            "revokedAt": date_value(revoked_at),
            "dN": f"C=IT,O=Example,CN={cn}" if cn else "C=IT,O=Example",
            "friendlyName": friendly_name,
            "user": user,
            "userEmail": email,
        }

    def _snapshot(self, records: list[dict[str, object]]) -> CacheSnapshot:
        return CacheSnapshot(
            schema_version=1,
            created_at=self.NOW - timedelta(hours=2),
            environment="production",
            base_url="https://cm.harica.gr",
            statuses=("valid", "revoked", "expired"),
            certificates=records,
        )

    def test_summary_counts_statuses_boundaries_and_missing_data(self) -> None:
        records = [
            self._record("07", valid_to=self.NOW + timedelta(days=7)),
            self._record(
                "08",
                valid_to=self.NOW + timedelta(days=7, seconds=1),
            ),
            self._record("30", valid_to=self.NOW + timedelta(days=30)),
            self._record(
                "31",
                valid_to=self.NOW + timedelta(days=30, seconds=1),
            ),
            self._record(
                "61",
                valid_to=self.NOW + timedelta(days=60, seconds=1),
            ),
            self._record(
                "91",
                valid_to=self.NOW + timedelta(days=90, seconds=1),
            ),
            self._record(
                "R",
                status="revoked",
                is_revoked=True,
                revoked_at=self.NOW - timedelta(days=10),
            ),
            self._record("E", status="expired"),
            self._record("U", status="pending"),
            self._record("", user="", email="", cn=""),
        ]
        records[-1]["validTo"] = "not-a-date"

        report = summary_report(self._snapshot(records), now=self.NOW)

        self.assertEqual(report["cache"]["ageHours"], 2)
        self.assertEqual(report["total"], 10)
        self.assertEqual(
            report["statusCounts"],
            {"valid": 7, "revoked": 1, "expired": 1, "unknown": 1},
        )
        self.assertEqual(
            report["expiryBuckets"],
            {
                "days0To7": 1,
                "days8To30": 2,
                "days31To60": 1,
                "days61To90": 1,
                "over90Days": 1,
            },
        )
        self.assertEqual(report["revokedLast30Days"], 1)
        self.assertEqual(report["missingUser"], 1)
        self.assertEqual(report["missingUserEmail"], 1)
        self.assertEqual(report["missingCN"], 1)
        self.assertEqual(report["invalidDates"], 1)
        self.assertEqual(list(summary_rows(report)[0]), ["metric", "value"])

    def test_summary_handles_an_empty_cache(self) -> None:
        report = summary_report(self._snapshot([]), now=self.NOW)
        self.assertEqual(report["total"], 0)
        self.assertEqual(sum(report["statusCounts"].values()), 0)
        self.assertEqual(sum(report["expiryBuckets"].values()), 0)

    def test_expirations_normalizes_timezones_sorts_and_warns(self) -> None:
        records = [
            self._record("B", valid_to=self.NOW + timedelta(days=2), cn="z.example"),
            self._record(
                "A",
                valid_to="2026-07-24T14:00:00+02:00",
                cn="a.example",
            ),
            self._record("X", status="expired", valid_to=self.NOW + timedelta(days=1)),
            self._record("BAD"),
        ]
        records[-1]["validTo"] = "invalid"

        report = expirations_report(records, within_days=2, now=self.NOW)

        self.assertEqual(report["withinDays"], 2)
        self.assertEqual(report["skippedInvalidDates"], 1)
        self.assertEqual(
            [row["serial"] for row in report["certificates"]],
            ["A", "B"],
        )
        self.assertEqual(report["certificates"][0]["validTo"], "2026-07-24T12:00:00Z")
        self.assertEqual(report["certificates"][0]["daysRemaining"], 1)
        with self.assertRaises(ValueError):
            expirations_report(records, within_days=0, now=self.NOW)

    def test_all_list_reports_handle_an_empty_cache(self) -> None:
        expirations = expirations_report([], now=self.NOW)
        self.assertEqual(expirations["certificates"], [])
        self.assertEqual(expirations["skippedInvalidDates"], 0)
        self.assertEqual(owners_report([], now=self.NOW), [])
        self.assertEqual(quality_report([]), [])

    def test_owners_groups_email_case_insensitively_and_separates_missing(self) -> None:
        records = [
            self._record(
                "1",
                email="PKI@example.org",
                user="Mario",
                valid_to=self.NOW + timedelta(days=10),
            ),
            self._record(
                "2",
                email="pki@example.org",
                user="M. Rossi",
                status="revoked",
                is_revoked=True,
                revoked_at=self.NOW,
            ),
            self._record("3", email="", user="", status="expired"),
        ]

        rows = owners_report(records, now=self.NOW)

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["total"], 2)
        self.assertEqual(rows[0]["valid"], 1)
        self.assertEqual(rows[0]["revoked"], 1)
        self.assertEqual(rows[0]["expiringWithin30Days"], 1)
        self.assertEqual(rows[0]["user"], "M. Rossi; Mario")
        self.assertEqual(rows[1]["userEmail"], "")
        self.assertEqual(rows[1]["expired"], 1)

    def test_quality_reports_every_supported_anomaly_with_stable_codes(self) -> None:
        duplicate_one = self._record("DUP")
        duplicate_two = self._record("dup")
        invalid = {
            "serial": "",
            "status": "pending",
            "validFrom": "bad",
            "validTo": None,
            "isRevoked": "yes",
            "revokedAt": "bad",
            "dN": "C=IT,O=Example",
            "friendlyName": "",
            "user": "",
            "userEmail": "",
        }
        missing_status = self._record("NO-STATUS")
        missing_status["status"] = ""
        range_error = self._record("RANGE")
        range_error["validFrom"] = "2026-07-24T00:00:00"
        range_error["validTo"] = "2026-07-23T00:00:00"
        mismatch = self._record("MISMATCH", is_revoked=True, revoked_at=None)

        rows = quality_report(
            [
                duplicate_one,
                duplicate_two,
                invalid,
                missing_status,
                range_error,
                mismatch,
            ]
        )
        issues = {row["issue"] for row in rows}

        self.assertTrue(
            {
                "duplicate_serial",
                "missing_serial",
                "unknown_status",
                "missing_status",
                "invalid_valid_from",
                "missing_valid_to",
                "invalid_is_revoked",
                "invalid_revoked_at",
                "missing_cn",
                "missing_user",
                "missing_user_email",
                "missing_friendly_name",
                "invalid_validity_range",
                "revocation_status_mismatch",
                "missing_revoked_at",
            }.issubset(issues)
        )
        self.assertEqual(
            sum(row["issue"] == "duplicate_serial" for row in rows),
            2,
        )
        self.assertEqual(
            rows,
            sorted(
                rows,
                key=lambda row: (
                    row["issue"],
                    row["serial"].casefold(),
                    row["CN"].casefold(),
                ),
            ),
        )

    def test_common_name_is_case_insensitive_and_decodes_dn_escapes(self) -> None:
        explicit = normalize_certificate({"commonNAME": "explicit.example"})
        derived = normalize_certificate(
            {"Dn": r"C=IT,O=Example,CN=Portal\, Produzione"}
        )
        utf8 = normalize_certificate({"dN": r"C=IT;CN=Jos\C3\A9"})
        self.assertEqual(explicit.cn, "explicit.example")
        self.assertEqual(derived.cn, "Portal, Produzione")
        self.assertEqual(utf8.cn, "José")


if __name__ == "__main__":
    unittest.main()
