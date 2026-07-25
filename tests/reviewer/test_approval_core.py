from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import unittest

from reviewer.approval import (
    APPROVAL_SOURCE_VERSION,
    APPROVAL_TTL,
    Approval,
    ApprovalSource,
    ApprovalStatus,
    ApprovalTtlDecision,
    AuthoritativeLabelEvent,
    LabelAction,
    evaluate_approval_ttl,
    fold_authoritative_label_prefix,
    github_clock_observation,
    new_uuid7,
    validate_approval_transition,
)


UTC = timezone.utc
EVENT_TIME = datetime(2026, 7, 25, 0, 0, tzinfo=UTC)


def label_event(
    ordinal: int,
    action: LabelAction,
    *,
    created_at: datetime | None = None,
    predecessor_event_id: str | None = None,
    **overrides: object,
) -> AuthoritativeLabelEvent:
    values: dict[str, object] = {
        "event_id": f"event-{ordinal}",
        "repository_id": 42,
        "pull_number": 7,
        "label_name": "hermes:merge-approved",
        "action": action,
        "actor_github_user_id": 101,
        "created_at": created_at or EVENT_TIME + timedelta(seconds=ordinal),
        "ordinal": ordinal,
        "predecessor_event_id": predecessor_event_id,
    }
    values.update(overrides)
    return AuthoritativeLabelEvent(**values)


class AuthoritativeTimelineFoldTests(unittest.TestCase):
    def test_generation_is_derived_from_complete_authoritative_prefix(self):
        events = (
            label_event(1, LabelAction.LABELED),
            label_event(2, LabelAction.UNLABELED, predecessor_event_id="event-1"),
            label_event(3, LabelAction.LABELED, predecessor_event_id="event-2"),
        )

        result = fold_authoritative_label_prefix(events)

        self.assertEqual([1, 1, 2], [item.generation for item in result.events])
        self.assertEqual([True, False, True], [item.label_is_active for item in result.events])
        self.assertEqual(2, result.latest_generation)
        self.assertEqual(2, result.active_generation)

    def test_empty_prefix_has_no_generation_or_active_label(self):
        result = fold_authoritative_label_prefix(())
        self.assertEqual((), result.events)
        self.assertEqual(0, result.latest_generation)
        self.assertIsNone(result.active_generation)

    def test_equal_timestamps_are_ordered_only_by_continuous_predecessor_chain(self):
        first = label_event(1, LabelAction.LABELED, created_at=EVENT_TIME)
        second = label_event(
            2,
            LabelAction.UNLABELED,
            created_at=EVENT_TIME,
            predecessor_event_id=first.event_id,
        )
        result = fold_authoritative_label_prefix((first, second))
        self.assertEqual([1, 1], [item.generation for item in result.events])

    def test_order_only_events_allow_non_user_or_missing_actor_identity(self):
        first = label_event(
            1,
            LabelAction.LABELED,
            actor_github_user_id=None,
        )
        second = label_event(
            2,
            LabelAction.UNLABELED,
            predecessor_event_id=first.event_id,
            actor_github_user_id=None,
        )
        result = fold_authoritative_label_prefix((first, second))
        self.assertEqual([1, 1], [item.generation for item in result.events])
        self.assertFalse(result.label_is_active)

    def test_gap_wrong_predecessor_duplicate_and_timestamp_regression_fail_closed(self):
        first = label_event(1, LabelAction.LABELED)
        second = label_event(
            2,
            LabelAction.UNLABELED,
            predecessor_event_id="event-1",
        )
        cases = (
            (first, label_event(3, LabelAction.UNLABELED, predecessor_event_id="event-1")),
            (first, label_event(2, LabelAction.UNLABELED, predecessor_event_id="other")),
            (
                first,
                second,
                replace(
                    first,
                    ordinal=3,
                    predecessor_event_id="event-2",
                    created_at=second.created_at + timedelta(seconds=1),
                ),
            ),
            (
                first,
                label_event(
                    2,
                    LabelAction.UNLABELED,
                    created_at=first.created_at - timedelta(seconds=1),
                    predecessor_event_id="event-1",
                ),
            ),
        )
        for events in cases:
            with self.subTest(events=events):
                with self.assertRaises(ValueError):
                    fold_authoritative_label_prefix(events)

    def test_cross_scope_and_impossible_label_state_fail_closed(self):
        first = label_event(1, LabelAction.LABELED)
        with self.assertRaisesRegex(ValueError, "crosses"):
            fold_authoritative_label_prefix(
                (
                    first,
                    label_event(
                        2,
                        LabelAction.UNLABELED,
                        predecessor_event_id="event-1",
                        pull_number=8,
                    ),
                )
            )
        for events in (
            (label_event(1, LabelAction.UNLABELED),),
            (
                first,
                label_event(2, LabelAction.LABELED, predecessor_event_id="event-1"),
            ),
        ):
            with self.subTest(events=events):
                with self.assertRaises(ValueError):
                    fold_authoritative_label_prefix(events)


class ApprovalTtlTests(unittest.TestCase):
    def clock(self, date_header: str | None, *, rtt_ns: int = 1_000_000_000):
        return github_clock_observation(
            date_header=date_header,
            request_started_monotonic_ns=10_000_000_000,
            response_received_monotonic_ns=10_000_000_000 + rtt_ns,
        )

    def test_ttl_uses_event_time_ten_minutes_date_resolution_rtt_and_elapsed(self):
        clock = self.clock("Sat, 25 Jul 2026 00:09:00 GMT")
        result = evaluate_approval_ttl(
            event_created_at=EVENT_TIME,
            clock=clock,
            now_monotonic_ns=clock.response_received_monotonic_ns + 27_000_000_000,
        )
        self.assertEqual(APPROVAL_TTL, result.expires_at - EVENT_TIME)
        self.assertEqual(datetime(2026, 7, 25, 0, 9, 29, tzinfo=UTC), result.server_now_upper)
        self.assertEqual(ApprovalTtlDecision.VALID, result.decision)

    def test_safety_margin_equality_is_terminal(self):
        clock = self.clock("Sat, 25 Jul 2026 00:09:27 GMT", rtt_ns=2_000_000_000)
        result = evaluate_approval_ttl(
            event_created_at=EVENT_TIME,
            clock=clock,
            now_monotonic_ns=clock.response_received_monotonic_ns,
        )
        self.assertEqual(datetime(2026, 7, 25, 0, 9, 30, tzinfo=UTC), result.server_now_upper)
        self.assertEqual(ApprovalTtlDecision.EXPIRED_OR_WITHIN_SAFETY_MARGIN, result.decision)
        self.assertFalse(result.is_valid)

    def test_two_second_rtt_is_allowed_but_any_greater_value_fails_closed(self):
        allowed = self.clock("Sat, 25 Jul 2026 00:00:00 GMT", rtt_ns=2_000_000_000)
        self.assertTrue(
            evaluate_approval_ttl(
                event_created_at=EVENT_TIME,
                clock=allowed,
                now_monotonic_ns=allowed.response_received_monotonic_ns,
            ).is_valid
        )
        rejected = self.clock("Sat, 25 Jul 2026 00:00:00 GMT", rtt_ns=2_000_000_001)
        self.assertEqual(
            ApprovalTtlDecision.REJECTED_REQUEST_RTT,
            evaluate_approval_ttl(
                event_created_at=EVENT_TIME,
                clock=rejected,
                now_monotonic_ns=rejected.response_received_monotonic_ns,
            ).decision,
        )

    def test_sub_microsecond_uncertainty_rounds_up_in_upper_bound(self):
        clock = self.clock("Sat, 25 Jul 2026 00:00:00 GMT", rtt_ns=1)
        result = evaluate_approval_ttl(
            event_created_at=EVENT_TIME,
            clock=clock,
            now_monotonic_ns=clock.response_received_monotonic_ns + 1,
        )
        self.assertEqual(
            datetime(2026, 7, 25, 0, 0, 1, 2, tzinfo=UTC),
            result.server_now_upper,
        )

    def test_missing_date_and_monotonic_regression_fail_closed(self):
        missing = self.clock(None)
        self.assertEqual(
            ApprovalTtlDecision.REJECTED_MISSING_GITHUB_DATE,
            evaluate_approval_ttl(
                event_created_at=EVENT_TIME,
                clock=missing,
                now_monotonic_ns=missing.response_received_monotonic_ns,
            ).decision,
        )
        regressed = self.clock("Sat, 25 Jul 2026 00:00:00 GMT")
        self.assertEqual(
            ApprovalTtlDecision.REJECTED_MONOTONIC_CLOCK,
            evaluate_approval_ttl(
                event_created_at=EVENT_TIME,
                clock=regressed,
                now_monotonic_ns=regressed.response_received_monotonic_ns - 1,
            ).decision,
        )

    def test_invalid_date_or_naive_event_time_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Date"):
            self.clock("not a date")
        with self.assertRaisesRegex(ValueError, "UTC"):
            evaluate_approval_ttl(
                event_created_at=EVENT_TIME.replace(tzinfo=None),
                clock=self.clock("Sat, 25 Jul 2026 00:00:00 GMT"),
                now_monotonic_ns=11_000_000_000,
            )


class ImmutableApprovalTests(unittest.TestCase):
    def approval(self, **overrides: object) -> Approval:
        attempt_id = new_uuid7(timestamp_ms=1, random_bits=1)
        values: dict[str, object] = {
            "approval_id": new_uuid7(timestamp_ms=2, random_bits=2),
            "source": ApprovalSource.GITHUB_LABEL,
            "source_version": APPROVAL_SOURCE_VERSION,
            "status": ApprovalStatus.PENDING,
            "repository_id": 42,
            "pull_number": 7,
            "review_context_id": f"dohwa-review-context-attempt/v1:{attempt_id}",
            "review_attempt_id": attempt_id,
            "content_id": "d" * 64,
            "label_event_id": "event-1",
            "webhook_delivery_id": "delivery-1",
            "approver_github_user_id": 101,
            "generation": 1,
            "event_created_at": EVENT_TIME,
            "accepted_at": EVENT_TIME + timedelta(seconds=1),
            "expires_at": EVENT_TIME + APPROVAL_TTL,
        }
        values.update(overrides)
        return Approval(**values)

    def test_identity_is_frozen_and_context_binds_exact_attempt(self):
        approval = self.approval()
        with self.assertRaises(FrozenInstanceError):
            approval.approval_id = new_uuid7()  # type: ignore[misc]
        other_attempt = new_uuid7(timestamp_ms=3, random_bits=3)
        with self.assertRaisesRegex(ValueError, "bind"):
            self.approval(review_attempt_id=other_attempt)

    def test_expiry_and_source_version_are_not_caller_selected(self):
        with self.assertRaisesRegex(ValueError, "derived"):
            self.approval(expires_at=EVENT_TIME + timedelta(minutes=11))
        with self.assertRaisesRegex(ValueError, "source version"):
            self.approval(source_version="approval-ttl/v2")

    def test_only_forward_nonterminal_status_transitions_are_allowed(self):
        for current, target in (
            (ApprovalStatus.PENDING, ApprovalStatus.ACTIVE),
            (ApprovalStatus.PENDING, ApprovalStatus.INVALIDATED),
            (ApprovalStatus.ACTIVE, ApprovalStatus.CONSUMED),
            (ApprovalStatus.ACTIVE, ApprovalStatus.INVALIDATED),
        ):
            validate_approval_transition(current, target)
        for current, target in (
            (ApprovalStatus.PENDING, ApprovalStatus.CONSUMED),
            (ApprovalStatus.ACTIVE, ApprovalStatus.PENDING),
            (ApprovalStatus.CONSUMED, ApprovalStatus.ACTIVE),
            (ApprovalStatus.INVALIDATED, ApprovalStatus.ACTIVE),
        ):
            with self.subTest(current=current, target=target):
                with self.assertRaises(ValueError):
                    validate_approval_transition(current, target)


if __name__ == "__main__":
    unittest.main()
